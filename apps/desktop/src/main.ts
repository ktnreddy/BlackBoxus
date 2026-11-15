import { mount } from "svelte";
import "@fontsource/dm-sans/latin-300.css";
import "@fontsource/dm-sans/latin-400.css";
import "@fontsource/dm-sans/latin-500.css";
import "@fontsource/dm-sans/latin-600.css";
import "@fontsource/dm-mono/latin-400.css";
import "@fontsource/dm-mono/latin-500.css";
import "./app.css";
import App from "./App.svelte";

const target = document.getElementById("app");
if (!target) throw new Error("missing #app");

export default mount(App, { target });
