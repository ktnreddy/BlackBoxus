//! Request handling and storage on Cloudflare Workers and D1.
//!
//! Every check is made by `server-core`; this module loads records, calls
//! the handlers and stores what they return. Binary values are stored in D1
//! as base64url text, and times as Unix milliseconds.

use std::cell::OnceCell;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use server_core::Error as CoreError;
use server_core::api::{
    AccountRecord, Api, EnrolmentTransfer, LOGIN_ID_LEN, MAX_ENROLMENT_BYTES, NewAccount,
    PendingLogin, SESSION_IDLE_MS, SESSION_MAX_MS, Session, accept_enrolment, session_token_hash,
    take_enrolment,
};
use server_core::log::MAX_ENTRY_BYTES;
use server_core::login::OpaqueServer;
use server_core::prelogin::FakeSaltKey;
use server_core::transparency::KtLog;
use server_core::vaults::{
    ItemWrite, MAX_ITEMS_PAGE, MAX_LOG_PAGE, accept_append, accept_owner_key, accept_share,
};
use vault_core::log::Checkpoint;
use vault_core::{
    AccountId, AccountSalt, ClientIdentity, IdentitySecretKey, KdfParams, MAX_ENVELOPE_LEN,
    OWNER_WRAPPED_VAULT_KEY_LEN, SIGNED_PUBLIC_BUNDLE_LEN, ServerIdentity, ShareInfo,
    VAULT_SHARE_LEN, VaultId, WRAPPED_KEY_SET_LEN,
};
use worker::wasm_bindgen::JsValue;
use worker::{
    Context, D1Database, D1PreparedStatement, Date, Env, Request, Response, ScheduleContext,
    ScheduledEvent, event,
};
use zeroize::Zeroizing;

use crate::http::{
    self, ApiError, EnrolmentGetResponse, EnrolmentPutRequest, KeySetResponse, Limit,
    LoginFinishRequest, LoginStartRequest, LoginStartResponse, PreloginRequest, PreloginResponse,
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
    Route, WrappedJson, b64, unb64, unb64_array,
};
use wire::{
    ItemJson, ItemsResponse, LogAppendRequest, LogAppendResponse, LogResponse, SharePostRequest,
    SharesResponse, VaultKeyPutRequest, VaultKeysResponse, VaultListResponse, VaultSummary,
};

/// Largest OPAQUE message or state accepted from a client or storage.
const MAX_OPAQUE_BYTES: usize = 1024;

/// Largest stored key transparency tree (D1 rows are limited to 2 MB).
const MAX_TREE_TEXT: usize = 2_000_000;

/// Sessions are written back at most this often when used.
const SESSION_TOUCH_MS: u64 = 3_600_000;

const MALFORMED: ApiError = ApiError::Core(CoreError::MalformedMessage);
const UNAUTHENTICATED: ApiError = ApiError::Core(CoreError::Authentication);

type Answer = Result<String, ApiError>;

thread_local! {
    static API: OnceCell<&'static Api> = const { OnceCell::new() };
}

/// The server's secrets, loaded once per isolate.
fn api(env: &Env) -> Result<&'static Api, ApiError> {
    if let Some(api) = API.with(|c| c.get().copied()) {
        return Ok(api);
    }
    let config = ApiError::Core(CoreError::InvalidConfiguration);
    let secret = |name: &str| -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let text = env.secret(name).map_err(|_| config)?.to_string();
        Ok(Zeroizing::new(unb64(&text, 4096).map_err(|_| config)?))
    };
    let origin = env.var("SERVER_ORIGIN").map_err(|_| config)?.to_string();
    let api = Api::new(
        OpaqueServer::from_bytes(&secret("OPAQUE_SETUP")?).map_err(|_| config)?,
        FakeSaltKey::from_bytes(&secret("FAKE_SALT_KEY")?).map_err(|_| config)?,
        IdentitySecretKey::from_seed_bytes(&secret("LOG_SIGNING_KEY")?).map_err(|_| config)?,
        ServerIdentity::new(&origin).map_err(|_| config)?,
    );
    let api: &'static Api = Box::leak(Box::new(api));
    API.with(|c| {
        let _ = c.set(api);
    });
    Ok(api)
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    let now = Date::now().as_millis();
    let (status, body, retry) = match handle(&mut req, &env, now).await {
        Ok(body) => (200, body, None),
        Err(e) => {
            let retry = match e {
                ApiError::RateLimited(s) => Some(s),
                _ => None,
            };
            (e.status(), e.body(), retry)
        }
    };
    let mut builder = Response::builder().with_status(status);
    for (k, v) in http::SECURITY_HEADERS {
        builder = builder.with_header(k, v)?;
    }
    if let Some(s) = retry {
        builder = builder.with_header("Retry-After", &s.to_string())?;
    }
    Ok(builder.fixed(body.into_bytes()))
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let now = Date::now().as_millis();
    if let Ok(db) = env.d1("DB") {
        // Best effort: anything missed is retried the next day.
        let _ = cleanup(&db, now).await;
    }
}

/// Deletes expired logins, transfers, sessions and rate limit windows.
async fn cleanup(db: &D1Database, now: u64) -> Result<(), ApiError> {
    let statements = vec![
        stmt(db, "DELETE FROM logins WHERE expires_ms <= ?1", &[num(now)])?,
        stmt(
            db,
            "DELETE FROM enrolments WHERE expires_ms <= ?1",
            &[num(now)],
        )?,
        stmt(
            db,
            "DELETE FROM sessions WHERE last_used_ms <= ?1 OR created_ms <= ?2",
            &[
                num(now.saturating_sub(SESSION_IDLE_MS)),
                num(now.saturating_sub(SESSION_MAX_MS)),
            ],
        )?,
        stmt(
            db,
            "DELETE FROM limits WHERE window_start_ms <= ?1",
            &[num(now.saturating_sub(86_400_000))],
        )?,
    ];
    db.batch(statements).await.map(|_| ()).map_err(storage)
}

async fn handle(req: &mut Request, env: &Env, now: u64) -> Answer {
    let route = http::route(req.method().as_ref(), &req.path())?;
    if route == Route::NotImplemented {
        return Err(ApiError::NotImplemented);
    }
    let api = api(env)?;
    let db = env.d1("DB").map_err(storage)?;
    let ip = req
        .headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_default();
    match route {
        Route::Prelogin => prelogin(req, &db, api, &ip, now).await,
        Route::RegisterStart => register_start(req, &db, api, &ip, now).await,
        Route::RegisterFinish => register_finish(req, &db, api, &ip, now).await,
        Route::LoginStart => login_start(req, &db, api, &ip, now).await,
        Route::LoginFinish => login_finish(req, &db, api, now).await,
        Route::Logout => {
            let session = authenticate(req, &db, api, now).await?;
            exec(
                &db,
                "DELETE FROM sessions WHERE token_hash = ?1",
                &[text(&b64(&session.token_hash))],
            )
            .await?;
            Ok("{}".into())
        }
        Route::KeySet => key_set(req, &db, api, now).await,
        Route::AccountKeys(id) => account_keys(req, &db, api, &id, now).await,
        Route::EnrolmentPut(id) => enrolment_put(req, &db, api, &id, now).await,
        Route::EnrolmentGet(id) => enrolment_get(&db, &id, &ip, now).await,
        Route::Vaults => vaults(req, &db, api, now).await,
        Route::LogAppend(v) => log_append(req, &db, api, &v, now).await,
        Route::LogRead(v) => log_read(req, &db, api, &v, now).await,
        Route::Items(v) => items(req, &db, api, &v, now).await,
        Route::VaultKeyPut(v) => vault_key_put(req, &db, api, &v, now).await,
        Route::VaultKeys(v) => vault_keys(req, &db, api, &v, now).await,
        Route::SharePost => share_post(req, &db, api, now).await,
        Route::Shares => shares(req, &db, api, now).await,
        Route::NotImplemented => Err(ApiError::NotImplemented),
    }
}

// ---------------------------------------------------------------------------
// Endpoints

async fn prelogin(req: &mut Request, db: &D1Database, api: &Api, ip: &str, now: u64) -> Answer {
    let r: PreloginRequest = body(req).await?;
    let identity = identity(&r.email)?;
    limit(db, &http::LOGIN_PER_IP, ip.as_bytes(), now).await?;
    limit(db, &http::LOGIN_PER_ADDRESS, identity.as_bytes(), now).await?;
    let account = account_by_email(db, &identity).await?;
    let (salt, kdf) = api.prelogin(&identity, account.as_ref())?;
    json(&PreloginResponse {
        salt: b64(salt.as_bytes()),
        kdf: kdf.into(),
    })
}

async fn register_start(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    ip: &str,
    now: u64,
) -> Answer {
    let r: RegisterStartRequest = body(req).await?;
    let identity = identity(&r.email)?;
    limit(db, &http::LOGIN_PER_IP, ip.as_bytes(), now).await?;
    let response = api.registration_response(&identity, &unb64(&r.request, MAX_OPAQUE_BYTES)?)?;
    json(&RegisterStartResponse {
        response: b64(&response),
    })
}

async fn register_finish(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    ip: &str,
    now: u64,
) -> Answer {
    let r: RegisterFinishRequest = body(req).await?;
    limit(db, &http::LOGIN_PER_IP, ip.as_bytes(), now).await?;
    let upload = unb64(&r.upload, MAX_OPAQUE_BYTES)?;
    let bundle = unb64(&r.signed_bundle, SIGNED_PUBLIC_BUNDLE_LEN)?;
    let wrapped = unb64(&r.wrapped_key_set, WRAPPED_KEY_SET_LEN)?;
    let (record, leaf) = api.create_account(
        &NewAccount {
            email: &r.email,
            salt: AccountSalt::from_bytes(unb64_array(&r.salt)?),
            kdf: KdfParams::from(r.kdf),
            registration_upload: &upload,
            signed_bundle: &bundle,
            wrapped_key_set: &wrapped,
        },
        now,
    )?;

    // Append to the key transparency log in the same transaction. The leaf
    // index is a primary key, so a concurrent append makes this fail with a
    // conflict instead of forking the log; the client retries.
    let state = kt_state(db).await?;
    let mut log = KtLog::from_stored(state.size, &unb64(&state.tree, MAX_TREE_TEXT)?)?;
    let old_size = log.size();
    let index = log.append(&leaf)?;
    let account_id = b64(record.account_id.as_bytes());
    let statements = vec![
        stmt(
            db,
            "INSERT INTO accounts (account_id, email, salt, kdf_m, kdf_t, kdf_p, opaque_record, \
             signed_bundle, key_set_version, wrapped_key_set, created_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            &[
                text(&account_id),
                text(record.identity.as_str()),
                text(&b64(record.salt.as_bytes())),
                num(u64::from(record.kdf.memory_kib)),
                num(u64::from(record.kdf.iterations)),
                num(u64::from(record.kdf.parallelism)),
                text(&b64(&record.opaque_record)),
                text(&b64(&record.signed_bundle)),
                num(u64::from(record.key_set_version)),
                text(&b64(&record.wrapped_key_set)),
                num(now),
            ],
        )?,
        stmt(
            db,
            "INSERT INTO kt_leaves (leaf_index, account_id, leaf) VALUES (?1, ?2, ?3)",
            &[num(index), text(&account_id), text(&b64(&leaf))],
        )?,
        stmt(
            db,
            "UPDATE kt_state SET size = ?1, tree = ?2 WHERE id = 1 AND size = ?3",
            &[num(log.size()), text(&b64(&log.to_stored())), num(old_size)],
        )?,
    ];
    let results = db.batch(statements).await.map_err(storage)?;
    // If the log moved on without a clash on the leaf index, something is
    // badly wrong; report a conflict rather than claim success.
    let updated = results
        .last()
        .and_then(|r| r.meta().ok().flatten())
        .and_then(|m| m.changes);
    if updated != Some(1) {
        return Err(ApiError::Core(CoreError::Conflict));
    }
    json(&RegisterFinishResponse { account_id })
}

async fn login_start(req: &mut Request, db: &D1Database, api: &Api, ip: &str, now: u64) -> Answer {
    let r: LoginStartRequest = body(req).await?;
    let identity = identity(&r.email)?;
    limit(db, &http::LOGIN_PER_IP, ip.as_bytes(), now).await?;
    limit(db, &http::LOGIN_PER_ADDRESS, identity.as_bytes(), now).await?;
    check_not_locked(db, &identity, now).await?;
    let account = account_by_email(db, &identity).await?;
    let ke1 = unb64(&r.ke1, MAX_OPAQUE_BYTES)?;
    let (pending, ke2) = api.start_login(&identity, account.as_ref(), &ke1, now)?;
    let login_id = b64(&pending.login_id);
    exec(
        db,
        "INSERT INTO logins (login_id, email, account_id, state, expires_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        &[
            text(&login_id),
            text(identity.as_str()),
            pending
                .account_id
                .map_or(JsValue::NULL, |id| text(&b64(id.as_bytes()))),
            text(&b64(&pending.state)),
            num(pending.expires_ms),
        ],
    )
    .await?;
    json(&LoginStartResponse {
        login_id,
        ke2: b64(&ke2),
    })
}

#[derive(Deserialize)]
struct LoginRow {
    email: String,
    account_id: Option<String>,
    state: String,
    expires_ms: u64,
}

async fn login_finish(req: &mut Request, db: &D1Database, api: &Api, now: u64) -> Answer {
    let r: LoginFinishRequest = body(req).await?;
    let login_id: [u8; LOGIN_ID_LEN] = unb64_array(&r.login_id)?;
    let ke3 = unb64(&r.ke3, MAX_OPAQUE_BYTES)?;
    // Deleted before checking, so each login can be tried only once.
    let row: LoginRow = first(
        db,
        "DELETE FROM logins WHERE login_id = ?1 RETURNING email, account_id, state, expires_ms",
        &[text(&b64(&login_id))],
    )
    .await?
    .ok_or(UNAUTHENTICATED)?;
    let identity = identity(&row.email)?;
    check_not_locked(db, &identity, now).await?;
    let pending = PendingLogin {
        login_id,
        identity: identity.clone(),
        account_id: row
            .account_id
            .as_deref()
            .map(|id| unb64_array(id).map(AccountId::from_bytes))
            .transpose()?,
        state: Zeroizing::new(unb64(&row.state, MAX_OPAQUE_BYTES)?),
        expires_ms: row.expires_ms,
    };
    match api.finish_login(pending, &ke3, now) {
        Ok(session) => {
            exec(
                db,
                "INSERT INTO sessions (token_hash, account_id, created_ms, last_used_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    text(&b64(&session.token_hash)),
                    text(&b64(session.account_id.as_bytes())),
                    num(session.created_ms),
                    num(session.last_used_ms),
                ],
            )
            .await?;
            Ok("{}".into())
        }
        Err(CoreError::Authentication) => {
            // Count the failure; reaching the limit locks the address.
            let _ = limit(db, &http::LOGIN_FAILURES, identity.as_bytes(), now).await;
            Err(UNAUTHENTICATED)
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize)]
struct KeySetRow {
    key_set_version: u32,
    wrapped_key_set: String,
}

async fn key_set(req: &Request, db: &D1Database, api: &Api, now: u64) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let row: KeySetRow = first(
        db,
        "SELECT key_set_version, wrapped_key_set FROM accounts WHERE account_id = ?1",
        &[text(&b64(session.account_id.as_bytes()))],
    )
    .await?
    .ok_or(ApiError::Storage)?;
    json(&KeySetResponse {
        account_id: b64(session.account_id.as_bytes()),
        key_set_version: row.key_set_version,
        wrapped: vec![WrappedJson {
            method: 1,
            data: row.wrapped_key_set,
        }],
    })
}

#[derive(Deserialize)]
struct LeafRow {
    leaf_index: u64,
    leaf: String,
}

async fn account_keys(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    id: &AccountId,
    now: u64,
) -> Answer {
    authenticate(req, db, api, now).await?;
    let seen = http::parse_seen(req.url().map_err(|_| MALFORMED)?.query())?;
    let account = account_by_id(db, id).await?.ok_or(ApiError::NotFound)?;
    let leaf: LeafRow = first(
        db,
        "SELECT leaf_index, leaf FROM kt_leaves WHERE account_id = ?1 \
         ORDER BY leaf_index DESC LIMIT 1",
        &[text(&b64(id.as_bytes()))],
    )
    .await?
    .ok_or(ApiError::Storage)?;
    let state = kt_state(db).await?;
    let log = KtLog::from_stored(state.size, &unb64(&state.tree, MAX_TREE_TEXT)?)?;

    // Tree heads are signed lazily, by the first lookup after the log grows,
    // which keeps registration well inside the CPU budget.
    let head = match state.sth {
        Some(sth) if state.sth_size == Some(state.size) => {
            unb64(&sth, vault_core::transparency::SIGNED_TREE_HEAD_LEN)?
        }
        _ => {
            let sth = api.sign_tree_head(&log, now)?;
            exec(
                db,
                "UPDATE kt_state SET sth = ?1, sth_size = ?2 WHERE id = 1 AND size = ?2",
                &[text(&b64(&sth)), num(state.size)],
            )
            .await?;
            sth
        }
    };
    let leaf_bytes = unb64(&leaf.leaf, vault_core::transparency::LEAF_LEN)?;
    let response =
        Api::key_lookup_with_head(&log, &account, &leaf_bytes, leaf.leaf_index, seen, head)?;
    json(&http::lookup_json(response))
}

async fn enrolment_put(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    id: &[u8; 16],
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let r: EnrolmentPutRequest = body(req).await?;
    let transfer = accept_enrolment(&unb64(&r.sealed, MAX_ENROLMENT_BYTES)?, now)?;
    exec(
        db,
        "INSERT INTO enrolments (session_id, account_id, sealed, expires_ms) VALUES (?1, ?2, ?3, ?4)",
        &[
            text(&b64(id)),
            text(&b64(session.account_id.as_bytes())),
            text(&b64(&transfer.sealed)),
            num(transfer.expires_ms),
        ],
    )
    .await?;
    Ok("{}".into())
}

#[derive(Deserialize)]
struct EnrolmentRow {
    sealed: String,
    expires_ms: u64,
}

async fn enrolment_get(db: &D1Database, id: &[u8; 16], ip: &str, now: u64) -> Answer {
    limit(db, &http::ENROLMENT_PER_IP, ip.as_bytes(), now).await?;
    // Deleted before answering, so a transfer can be downloaded only once.
    let row: Option<EnrolmentRow> = first(
        db,
        "DELETE FROM enrolments WHERE session_id = ?1 RETURNING sealed, expires_ms",
        &[text(&b64(id))],
    )
    .await?;
    let transfer = row
        .map(|r| {
            Ok::<_, ApiError>(EnrolmentTransfer {
                sealed: unb64(&r.sealed, MAX_ENROLMENT_BYTES)?,
                expires_ms: r.expires_ms,
            })
        })
        .transpose()?;
    let sealed = take_enrolment(transfer, now)?;
    json(&EnrolmentGetResponse {
        sealed: b64(&sealed),
    })
}

// ---------------------------------------------------------------------------
// Vaults

async fn may_read(db: &D1Database, vault: &str, account: &str) -> Result<bool, ApiError> {
    #[derive(Deserialize)]
    struct One {
        #[allow(dead_code, reason = "presence is what matters")]
        one: u32,
    }
    let row: Option<One> = first(
        db,
        "SELECT 1 AS one FROM vault_access WHERE vault_id = ?1 AND account_id = ?2",
        &[text(vault), text(account)],
    )
    .await?;
    Ok(row.is_some())
}

async fn require_read(db: &D1Database, vault: &str, account: &str) -> Result<(), ApiError> {
    if may_read(db, vault, account).await? {
        Ok(())
    } else {
        Err(ApiError::Core(CoreError::NotAllowed))
    }
}

#[derive(Deserialize)]
struct VaultRow {
    vault_id: String,
    head_seq: u64,
}

async fn vaults(req: &Request, db: &D1Database, api: &Api, now: u64) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let rows: Vec<VaultRow> = all(
        db,
        "SELECT a.vault_id AS vault_id, MAX(l.seq) AS head_seq FROM vault_access a \
         JOIN vault_log l ON l.vault_id = a.vault_id WHERE a.account_id = ?1 GROUP BY a.vault_id",
        &[text(&b64(session.account_id.as_bytes()))],
    )
    .await?;
    json(&VaultListResponse {
        vaults: rows
            .into_iter()
            .map(|r| VaultSummary {
                vault_id: r.vault_id,
                head_seq: r.head_seq,
            })
            .collect(),
    })
}

#[derive(Deserialize)]
struct HeadRow {
    seq: u64,
    hash: String,
}

async fn log_append(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    vault_id: &VaultId,
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let r: LogAppendRequest = body(req).await?;
    let entry = unb64(&r.entry, MAX_ENTRY_BYTES)?;
    let envelope = r
        .envelope
        .as_deref()
        .map(|e| unb64(e, MAX_ENVELOPE_LEN))
        .transpose()?;
    let vault = b64(vault_id.as_bytes());
    let account = b64(session.account_id.as_bytes());
    let head: Option<HeadRow> = first(
        db,
        "SELECT seq, hash FROM vault_log WHERE vault_id = ?1 ORDER BY seq DESC LIMIT 1",
        &[text(&vault)],
    )
    .await?;
    let head = head
        .map(|h| {
            Ok::<_, ApiError>(Checkpoint {
                seq: h.seq,
                hash: unb64_array(&h.hash)?,
            })
        })
        .transpose()?;
    let readable = head.is_some() && may_read(db, &vault, &account).await?;
    let accepted = accept_append(
        vault_id,
        head.as_ref(),
        readable,
        &session.account_id,
        &entry,
        envelope.as_deref(),
    )?;
    let seq = accepted.checkpoint.seq;
    let mut statements = vec![stmt(
        db,
        "INSERT INTO vault_log (vault_id, seq, entry, hash) VALUES (?1, ?2, ?3, ?4)",
        &[
            text(&vault),
            num(seq),
            text(&b64(&entry)),
            text(&b64(&accepted.checkpoint.hash)),
        ],
    )?];
    if accepted.creates_vault {
        statements.push(stmt(
            db,
            "INSERT INTO vault_access (vault_id, account_id) VALUES (?1, ?2)",
            &[text(&vault), text(&account)],
        )?);
    }
    let upsert = "INSERT INTO vault_items (vault_id, item_id, revision, envelope, seq) \
                  VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (vault_id, item_id) DO UPDATE SET \
                  revision = excluded.revision, envelope = excluded.envelope, seq = excluded.seq";
    match &accepted.item {
        Some(ItemWrite::Put {
            item_id,
            revision,
            envelope,
        }) => statements.push(stmt(
            db,
            upsert,
            &[
                text(&vault),
                text(&b64(item_id.as_bytes())),
                num(*revision),
                text(&b64(envelope)),
                num(seq),
            ],
        )?),
        Some(ItemWrite::Delete { item_id, revision }) => statements.push(stmt(
            db,
            upsert,
            &[
                text(&vault),
                text(&b64(item_id.as_bytes())),
                num(*revision),
                JsValue::NULL,
                num(seq),
            ],
        )?),
        None => {}
    }
    db.batch(statements).await.map_err(storage)?;
    json(&LogAppendResponse { seq })
}

#[derive(Deserialize)]
struct EntryRow {
    entry: String,
}

async fn log_read(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    vault_id: &VaultId,
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let from = http::parse_number(req.url().map_err(|_| MALFORMED)?.query(), "from")?.unwrap_or(0);
    let vault = b64(vault_id.as_bytes());
    require_read(db, &vault, &b64(session.account_id.as_bytes())).await?;
    let mut rows: Vec<EntryRow> = all(
        db,
        "SELECT entry FROM vault_log WHERE vault_id = ?1 AND seq >= ?2 ORDER BY seq LIMIT ?3",
        &[text(&vault), num(from), num(page_plus_one(MAX_LOG_PAGE))],
    )
    .await?;
    let more = rows.len() > MAX_LOG_PAGE;
    rows.truncate(MAX_LOG_PAGE);
    json(&LogResponse {
        entries: rows.into_iter().map(|r| r.entry).collect(),
        more,
    })
}

#[derive(Deserialize)]
struct ItemRow {
    item_id: String,
    revision: u64,
    envelope: Option<String>,
    seq: u64,
}

async fn items(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    vault_id: &VaultId,
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let after = http::parse_number(req.url().map_err(|_| MALFORMED)?.query(), "after")?;
    let vault = b64(vault_id.as_bytes());
    require_read(db, &vault, &b64(session.account_id.as_bytes())).await?;
    // Without `after`, everything; `-1` is below every sequence number.
    let after = after.map_or(JsValue::from_f64(-1.0), num);
    let mut rows: Vec<ItemRow> = all(
        db,
        "SELECT item_id, revision, envelope, seq FROM vault_items \
         WHERE vault_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        &[text(&vault), after, num(page_plus_one(MAX_ITEMS_PAGE))],
    )
    .await?;
    let more = rows.len() > MAX_ITEMS_PAGE;
    rows.truncate(MAX_ITEMS_PAGE);
    json(&ItemsResponse {
        items: rows
            .into_iter()
            .map(|r| ItemJson {
                item_id: r.item_id,
                revision: r.revision,
                envelope: r.envelope,
                seq: r.seq,
            })
            .collect(),
        more,
    })
}

async fn vault_key_put(
    req: &mut Request,
    db: &D1Database,
    api: &Api,
    vault_id: &VaultId,
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let r: VaultKeyPutRequest = body(req).await?;
    let wrapped = unb64(&r.wrapped, OWNER_WRAPPED_VAULT_KEY_LEN)?;
    let vault = b64(vault_id.as_bytes());
    let account = b64(session.account_id.as_bytes());
    let version = accept_owner_key(vault_id, may_read(db, &vault, &account).await?, &wrapped)?;
    exec(
        db,
        "INSERT INTO vault_keys (vault_id, account_id, version, wrapped) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (vault_id, account_id, version) DO UPDATE SET wrapped = excluded.wrapped",
        &[
            text(&vault),
            text(&account),
            num(u64::from(version)),
            text(&b64(&wrapped)),
        ],
    )
    .await?;
    Ok("{}".into())
}

#[derive(Deserialize)]
struct WrappedRow {
    wrapped: String,
}

async fn vault_keys(
    req: &Request,
    db: &D1Database,
    api: &Api,
    vault_id: &VaultId,
    now: u64,
) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let rows: Vec<WrappedRow> = all(
        db,
        "SELECT wrapped FROM vault_keys WHERE vault_id = ?1 AND account_id = ?2 ORDER BY version",
        &[
            text(&b64(vault_id.as_bytes())),
            text(&b64(session.account_id.as_bytes())),
        ],
    )
    .await?;
    json(&VaultKeysResponse {
        keys: rows.into_iter().map(|r| r.wrapped).collect(),
    })
}

async fn share_post(req: &mut Request, db: &D1Database, api: &Api, now: u64) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let r: SharePostRequest = body(req).await?;
    let share = unb64(&r.share, VAULT_SHARE_LEN)?;
    let account = b64(session.account_id.as_bytes());
    let vault_of = ShareInfo::inspect(&share).map_err(|_| MALFORMED)?.vault_id;
    let vault = b64(vault_of.as_bytes());
    let info = accept_share(
        &share,
        &session.account_id,
        may_read(db, &vault, &account).await?,
    )?;
    let recipient = b64(info.recipient.as_bytes());
    let statements = vec![
        stmt(
            db,
            "INSERT INTO shares (recipient, vault_id, version, sender, share, created_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (recipient, vault_id, version, sender) \
             DO UPDATE SET share = excluded.share, created_ms = excluded.created_ms",
            &[
                text(&recipient),
                text(&vault),
                num(u64::from(info.vault_key_version)),
                text(&account),
                text(&b64(&share)),
                num(now),
            ],
        )?,
        stmt(
            db,
            "INSERT OR IGNORE INTO vault_access (vault_id, account_id) VALUES (?1, ?2)",
            &[text(&vault), text(&recipient)],
        )?,
    ];
    db.batch(statements).await.map_err(storage)?;
    Ok("{}".into())
}

#[derive(Deserialize)]
struct ShareRow {
    share: String,
}

async fn shares(req: &Request, db: &D1Database, api: &Api, now: u64) -> Answer {
    let session = authenticate(req, db, api, now).await?;
    let rows: Vec<ShareRow> = all(
        db,
        "SELECT share FROM shares WHERE recipient = ?1 ORDER BY created_ms LIMIT 500",
        &[text(&b64(session.account_id.as_bytes()))],
    )
    .await?;
    json(&SharesResponse {
        shares: rows.into_iter().map(|r| r.share).collect(),
    })
}

fn page_plus_one(page: usize) -> u64 {
    u64::try_from(page).unwrap_or(u64::MAX).saturating_add(1)
}

// ---------------------------------------------------------------------------
// Sessions and rate limits

#[derive(Deserialize)]
struct SessionRow {
    account_id: String,
    created_ms: u64,
    last_used_ms: u64,
}

/// Checks the bearer token and applies the per-session rate limit.
async fn authenticate(
    req: &Request,
    db: &D1Database,
    api: &Api,
    now: u64,
) -> Result<Session, ApiError> {
    let header = req.headers().get("Authorization").ok().flatten();
    let token = Zeroizing::new(http::bearer_token(header.as_deref())?);
    let hash = session_token_hash(&token)?;
    let key = b64(&hash);
    let row: Option<SessionRow> = first(
        db,
        "SELECT account_id, created_ms, last_used_ms FROM sessions WHERE token_hash = ?1",
        &[text(&key)],
    )
    .await?;
    let stored = row
        .map(|r| {
            Ok::<_, ApiError>(Session {
                token_hash: hash,
                account_id: AccountId::from_bytes(unb64_array(&r.account_id)?),
                created_ms: r.created_ms,
                last_used_ms: r.last_used_ms,
            })
        })
        .transpose()?;
    let session = match api.authenticate(&token, stored.as_ref(), now) {
        Ok(s) => s,
        Err(e) => {
            if stored.is_some() {
                // Expired: remove it now rather than wait for the cleanup.
                let _ = exec(
                    db,
                    "DELETE FROM sessions WHERE token_hash = ?1",
                    &[text(&key)],
                )
                .await;
            }
            return Err(e.into());
        }
    };
    limit(db, &http::PER_SESSION, &hash, now).await?;
    if stored.is_some_and(|s| now.saturating_sub(s.last_used_ms) >= SESSION_TOUCH_MS) {
        exec(
            db,
            "UPDATE sessions SET last_used_ms = ?1 WHERE token_hash = ?2",
            &[num(now), text(&key)],
        )
        .await?;
    }
    Ok(session)
}

#[derive(Deserialize)]
struct LimitRow {
    count: u32,
    window_start_ms: u64,
}

/// Counts one request against `limit`, failing once it is exceeded.
async fn limit(db: &D1Database, limit: &Limit, subject: &[u8], now: u64) -> Result<(), ApiError> {
    let row: LimitRow = first(
        db,
        "INSERT INTO limits (key, window_start_ms, count) VALUES (?1, ?2, 1) \
         ON CONFLICT (key) DO UPDATE SET \
           count = CASE WHEN window_start_ms <= ?3 THEN 1 ELSE count + 1 END, \
           window_start_ms = CASE WHEN window_start_ms <= ?3 THEN ?2 ELSE window_start_ms END \
         RETURNING count, window_start_ms",
        &[
            text(&limit.key(subject)),
            num(now),
            num(now.saturating_sub(limit.window_ms)),
        ],
    )
    .await?
    .ok_or(ApiError::Storage)?;
    if row.count > limit.max {
        return Err(ApiError::RateLimited(
            limit.retry_after(row.window_start_ms, now),
        ));
    }
    Ok(())
}

/// Fails while an address is locked after too many failed logins.
async fn check_not_locked(
    db: &D1Database,
    identity: &ClientIdentity,
    now: u64,
) -> Result<(), ApiError> {
    let failures = &http::LOGIN_FAILURES;
    let row: Option<LimitRow> = first(
        db,
        "SELECT count, window_start_ms FROM limits WHERE key = ?1",
        &[text(&failures.key(identity.as_bytes()))],
    )
    .await?;
    match row {
        Some(r)
            if r.count >= failures.max
                && now < r.window_start_ms.saturating_add(failures.window_ms) =>
        {
            Err(ApiError::RateLimited(
                failures.retry_after(r.window_start_ms, now),
            ))
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Accounts and the key log

#[derive(Deserialize)]
struct AccountRow {
    account_id: String,
    email: String,
    salt: String,
    kdf_m: u32,
    kdf_t: u32,
    kdf_p: u32,
    opaque_record: String,
    signed_bundle: String,
    key_set_version: u32,
    wrapped_key_set: String,
}

impl TryFrom<AccountRow> for AccountRecord {
    type Error = ApiError;

    fn try_from(r: AccountRow) -> Result<Self, ApiError> {
        Ok(Self {
            account_id: AccountId::from_bytes(unb64_array(&r.account_id)?),
            identity: identity(&r.email)?,
            salt: AccountSalt::from_bytes(unb64_array(&r.salt)?),
            kdf: KdfParams {
                memory_kib: r.kdf_m,
                iterations: r.kdf_t,
                parallelism: r.kdf_p,
            },
            opaque_record: unb64(&r.opaque_record, MAX_OPAQUE_BYTES)?,
            signed_bundle: unb64(&r.signed_bundle, SIGNED_PUBLIC_BUNDLE_LEN)?,
            key_set_version: r.key_set_version,
            wrapped_key_set: unb64(&r.wrapped_key_set, WRAPPED_KEY_SET_LEN)?,
        })
    }
}

const ACCOUNT_COLUMNS: &str = "account_id, email, salt, kdf_m, kdf_t, kdf_p, opaque_record, \
                               signed_bundle, key_set_version, wrapped_key_set";

async fn account_by_email(
    db: &D1Database,
    identity: &ClientIdentity,
) -> Result<Option<AccountRecord>, ApiError> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE email = ?1");
    let row: Option<AccountRow> = first(db, &sql, &[text(identity.as_str())]).await?;
    row.map(AccountRecord::try_from).transpose()
}

async fn account_by_id(db: &D1Database, id: &AccountId) -> Result<Option<AccountRecord>, ApiError> {
    let sql = format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE account_id = ?1");
    let row: Option<AccountRow> = first(db, &sql, &[text(&b64(id.as_bytes()))]).await?;
    row.map(AccountRecord::try_from).transpose()
}

#[derive(Deserialize)]
struct KtStateRow {
    size: u64,
    tree: String,
    sth: Option<String>,
    sth_size: Option<u64>,
}

async fn kt_state(db: &D1Database) -> Result<KtStateRow, ApiError> {
    first(
        db,
        "SELECT size, tree, sth, sth_size FROM kt_state WHERE id = 1",
        &[],
    )
    .await?
    .ok_or(ApiError::Storage)
}

// ---------------------------------------------------------------------------
// Helpers

fn identity(email: &str) -> Result<ClientIdentity, ApiError> {
    ClientIdentity::new(email).map_err(|_| MALFORMED)
}

async fn body<T: DeserializeOwned>(req: &mut Request) -> Result<T, ApiError> {
    let declared = req
        .headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > http::MAX_BODY_BYTES) {
        return Err(MALFORMED);
    }
    let bytes = req.bytes().await.map_err(|_| MALFORMED)?;
    http::parse_json(&bytes)
}

fn json<T: serde::Serialize>(value: &T) -> Answer {
    serde_json::to_string(value).map_err(|_| ApiError::Storage)
}

fn text(s: &str) -> JsValue {
    JsValue::from_str(s)
}

/// Times and sizes stay far below 2^53, so they are exact as JS numbers.
#[allow(clippy::cast_precision_loss, reason = "values stay below 2^53")]
fn num(n: u64) -> JsValue {
    JsValue::from_f64(n as f64)
}

fn storage(e: worker::Error) -> ApiError {
    let message = e.to_string();
    if message.contains("constraint") || message.contains("CONSTRAINT") {
        ApiError::Core(CoreError::Conflict)
    } else {
        ApiError::Storage
    }
}

fn stmt(db: &D1Database, sql: &str, args: &[JsValue]) -> Result<D1PreparedStatement, ApiError> {
    db.prepare(sql).bind(args).map_err(storage)
}

async fn exec(db: &D1Database, sql: &str, args: &[JsValue]) -> Result<(), ApiError> {
    stmt(db, sql, args)?
        .run()
        .await
        .map(|_| ())
        .map_err(storage)
}

async fn all<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    args: &[JsValue],
) -> Result<Vec<T>, ApiError> {
    stmt(db, sql, args)?
        .all()
        .await
        .map_err(storage)?
        .results()
        .map_err(|_| ApiError::Storage)
}

async fn first<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    args: &[JsValue],
) -> Result<Option<T>, ApiError> {
    stmt(db, sql, args)?.first(None).await.map_err(storage)
}
