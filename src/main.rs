#![allow(non_snake_case)]

use crate::icons::*;
use anyhow::Result;
use dioxus::prelude::*;
use dioxus_html_macro::html;
use dioxus_liveview::LiveViewPool;
use dioxus_ssr::render_lazy;
use once_cell::sync::OnceCell;
use rand::Rng;
use rust_embed::RustEmbed;
use salvo::affix;
use salvo::csrf::{aes_gcm_session_csrf, CsrfDepotExt, FormFinder};
use salvo::hyper::header::ORIGIN;
use salvo::hyper::Method;
use salvo::prelude::*;
use salvo::serve_static::static_embed;
use salvo::session::SessionDepotExt;
use salvo::session::SessionHandler;
use serde::Deserialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqliteJournalMode;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::sqlite::SqliteSynchronous;
use sqlx::SqlitePool;
use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::Level;

mod icons;

const HOME: &str = "/";
const APP: &str = "/app";
const LOGIN: &str = "/login";
const LOGOUT: &str = "/logout";

#[derive(RustEmbed)]
#[folder = "static"]
struct Assets;

pub static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();

pub fn db() -> &'static SqlitePool {
    DB_POOL.get().unwrap()
}

pub async fn make_db_pool(database_url: &str) -> SqlitePool {
    let connection_options = SqliteConnectOptions::from_str(database_url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(30));
    return SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connection_options)
        .await
        .unwrap();
}

fn at(path: &str) -> Router {
    Router::with_path(path)
}

fn routes() -> Router {
    let session_key = env::var("SESSION_KEY").unwrap();
    let session_handler =
        SessionHandler::builder(salvo::session::CookieStore::new(), session_key.as_bytes())
            .cookie_name("id")
            .same_site_policy(salvo::http::cookie::SameSite::Strict)
            .build()
            .unwrap();
    let form_finder = FormFinder::new("csrf_token");
    let csrf_key: [u8; 32] = env::var("CSRF_KEY").unwrap().as_bytes().try_into().unwrap();
    let csrf_handler = aes_gcm_session_csrf(csrf_key, form_finder.clone());
    let view = LiveViewPool::new();
    let arc_view = Arc::new(view);

    return Router::new()
        .push(
            Router::new()
                .hoop(session_handler)
                .hoop(csrf_handler)
                .get(home)
                .post(signup)
                .push(at(LOGIN).get(get_login).post(post_login))
                .push(at(LOGOUT).post(logout))
                .hoop(affix::inject(arc_view))
                .push(at("/app").get(app_handler))
                .push(at("/ws").get(connect)),
        )
        .push(at("<**path>").get(static_embed::<Assets>()));
}

#[inline_props]
fn Form<'a>(cx: Scope, action: Option<&'a str>, children: Element<'a>) -> Element<'a> {
    let csrf_token = use_shared_state::<AppState>(cx)
        .unwrap()
        .read()
        .csrf_token
        .clone();
    let method = Method::POST;
    let act = action.unwrap_or("");
    cx.render(html! {
        <form action="{act}" method="{method}">
            <input r#type="hidden" value="{csrf_token}" name="csrf_token" />
            {&cx.props.children}
        </form>
    })
}

#[derive(Default, PartialEq)]
struct AppState {
    csrf_token: String,
    user: Option<User>,
}

#[inline_props]
fn Layout<'a>(
    cx: Scope,
    csrf_token: &'a str,
    user: Option<User>,
    children: Element<'a>,
) -> Element<'a> {
    use_shared_state_provider(cx, || AppState {
        csrf_token: csrf_token.to_string(),
        user: user.clone(),
    });

    let username = match user {
        Some(u) => u.username.clone(),
        None => String::default(),
    };

    cx.render(
        html! {
            "<!DOCTYPE html>"
            "<html lang=en>"
                <head>
                    <title>"all your links"</title>
                    <meta charset="utf-8" />
                    <meta name="viewport" content="width=device-width" />
                    <link rel="stylesheet" href="/output.css" />
                </head>
                <body class="dark:bg-zinc-900 dark:text-yellow-400 bg-yellow-400 text-zinc-900 font-sans max-w-3xl mx-auto">
                    <Nav username={username} />
                    {&cx.props.children}
                </body>
            "</html>"
        }
    )
}

#[derive(PartialEq)]
struct CreateUserError {}

impl std::fmt::Display for CreateUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid username")
    }
}

fn Header(cx: Scope) -> Element {
    cx.render(
        html! {
            <header class="flex flex-col gap-1 text-center">
                <h1 class="font-bold text-5xl lg:text-7xl">
                    <a href={HOME}>"all your links"</a>
                </h1>
                <p class="max-w-md mx-auto">"Share everything you create, sell or curate behind one link"</p>
            </header>
        }
    )
}
#[inline_props]
fn Home(cx: Scope, error: Option<CreateUserError>) -> Element {
    let err = match error {
        Some(err) => err.to_string(),
        None => String::default(),
    };
    cx.render(
        html! {
            <div class="flex flex-col gap-16">
                <Header />
                <Form action="/">
                    <div class="flex flex-col gap-2 md:max-w-lg md:mx-auto">
                        <div class="flex flex-col">
                            <div class="dark:text-white text-black">{err}</div>
                            <TextField name="username" autofocus={true} />
                        </div>
                        <Cta>"Claim your username"</Cta>
                    </div>
                </Form>
                <div class="grid grid-cols-4 gap-8 md:mx-auto">
                    <Twitch />
                    <Twitter />
                    <Instagram />
                    <Youtube />
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-tiktok" view_box="0 0 16 16">
                      <path d="M9 0h1.98c.144.715.54 1.617 1.235 2.512C12.895 3.389 13.797 4 15 4v2c-1.753 0-3.07-.814-4-1.829V11a5 5 0 1 1-5-5v2a3 3 0 1 0 3 3V0Z"/>
                    </svg>
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-discord" view_box="0 0 16 16">
                      <path d="M13.545 2.907a13.227 13.227 0 0 0-3.257-1.011.05.05 0 0 0-.052.025c-.141.25-.297.577-.406.833a12.19 12.19 0 0 0-3.658 0 8.258 8.258 0 0 0-.412-.833.051.051 0 0 0-.052-.025c-1.125.194-2.22.534-3.257 1.011a.041.041 0 0 0-.021.018C.356 6.024-.213 9.047.066 12.032c.001.014.01.028.021.037a13.276 13.276 0 0 0 3.995 2.02.05.05 0 0 0 .056-.019c.308-.42.582-.863.818-1.329a.05.05 0 0 0-.01-.059.051.051 0 0 0-.018-.011 8.875 8.875 0 0 1-1.248-.595.05.05 0 0 1-.02-.066.051.051 0 0 1 .015-.019c.084-.063.168-.129.248-.195a.05.05 0 0 1 .051-.007c2.619 1.196 5.454 1.196 8.041 0a.052.052 0 0 1 .053.007c.08.066.164.132.248.195a.051.051 0 0 1-.004.085 8.254 8.254 0 0 1-1.249.594.05.05 0 0 0-.03.03.052.052 0 0 0 .003.041c.24.465.515.909.817 1.329a.05.05 0 0 0 .056.019 13.235 13.235 0 0 0 4.001-2.02.049.049 0 0 0 .021-.037c.334-3.451-.559-6.449-2.366-9.106a.034.034 0 0 0-.02-.019Zm-8.198 7.307c-.789 0-1.438-.724-1.438-1.612 0-.889.637-1.613 1.438-1.613.807 0 1.45.73 1.438 1.613 0 .888-.637 1.612-1.438 1.612Zm5.316 0c-.788 0-1.438-.724-1.438-1.612 0-.889.637-1.613 1.438-1.613.807 0 1.451.73 1.438 1.613 0 .888-.631 1.612-1.438 1.612Z"/>
                    </svg>
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-github" view_box="0 0 16 16">
                      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
                    </svg>
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-stack-overflow" view_box="0 0 16 16">
                      <path d="M12.412 14.572V10.29h1.428V16H1v-5.71h1.428v4.282h9.984z"/>
                      <path d="M3.857 13.145h7.137v-1.428H3.857v1.428zM10.254 0 9.108.852l4.26 5.727 1.146-.852L10.254 0zm-3.54 3.377 5.484 4.567.913-1.097L7.627 2.28l-.914 1.097zM4.922 6.55l6.47 3.013.603-1.294-6.47-3.013-.603 1.294zm-.925 3.344 6.985 1.469.294-1.398-6.985-1.468-.294 1.397z"/>
                    </svg>
                </div>
            </div>
        }
    )
}

#[handler]
async fn home(depot: &mut Depot) -> Text<String> {
    let new_token = depot.csrf_token().map(|s| &**s).unwrap_or_default();
    let user_id: Option<i64> = depot.session().unwrap().get("user_id");
    let user: User = match user_id {
        Some(id) => sqlx::query_as!(User, "select * from users where id = ?", id)
            .fetch_one(db())
            .await
            .unwrap(),
        None => User::default(),
    };

    Text::Html(render_lazy(html! {
        <Layout csrf_token={new_token} user={user}>
            <Home />
        </Layout>
    }))
}

#[derive(Default, Debug, PartialEq, Clone)]
struct User {
    id: i64,
    username: String,
    login_code: String,
    updated_at: Option<i64>,
    created_at: i64,
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
}

impl NewUser {
    async fn insert(&self) -> Result<User, sqlx::Error> {
        let mut login_code: String = String::new();
        for _ in 0..16 {
            login_code.push_str(rand::thread_rng().gen_range(0..10).to_string().as_ref());
        }
        let id: i64 = sqlx::query!(
            "insert into users (username, login_code) values (?, ?)",
            self.username,
            login_code
        )
        .execute(db())
        .await?
        .last_insert_rowid();
        return sqlx::query_as!(User, "select * from users where id = ?", id)
            .fetch_one(db())
            .await;
    }
}

#[handler]
async fn signup(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<()> {
    let new_user: NewUser = req.parse_form().await?;
    let user: User = new_user.insert().await?;
    let session = depot.session_mut().unwrap();
    _ = session.insert("user_id", user.id)?;
    res.render(Redirect::other(APP));
    return Ok(());
}

#[handler]
fn get_login() {}

#[handler]
fn post_login() {}

#[handler]
fn logout(depot: &mut Depot, res: &mut Response) {
    let session = depot.session_mut().unwrap();
    session.remove("user_id");
    res.render(Redirect::other(HOME));
}

#[derive(PartialEq, Props)]
struct AppProps {
    user: User,
}

fn app(cx: Scope<AppProps>) -> Element {
    let mut num = use_state(cx, || 0);
    let times = if *num.get() == 1 { "time" } else { "times" };

    cx.render(html! {
        <div class="flex gap-2">
            "you are logged in as: @{&cx.props.user.username}"
            "you clicked this {num} {times}"
            <Button onclick={move |_| num += 1}>"click me"</Button>
        </div>
    })
}

#[inline_props]
fn Cta<'a>(cx: Scope, children: Element<'a>) -> Element<'a> {
    cx.render(
        html! {
            <button class="dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full">{&cx.props.children}</button>
        }
    )
}

#[inline_props]
fn Submit<'a>(cx: Scope, value: &'a str) -> Element<'a> {
    cx.render(html! {
        <input r#type="submit" value={*value} class="cursor-pointer" />
    })
}

#[inline_props]
fn Nav(cx: Scope, username: Option<String>) -> Element {
    let name = username.clone().unwrap_or_default();
    let href_profile = match username {
        Some(u) => format!("/@{}", u),
        None => String::default(),
    };

    cx.render(html! {
        <nav class="flex gap-8 justify-center py-8">
            <a href={HOME}>"Home"</a>
            {
                if name != String::default() {
                    cx.render(
                        html! {
                            <div class="flex gap-8">
                                <a href="{href_profile}">"Profile"</a>
                                <Form action={LOGOUT}>
                                    <Submit value="Logout" />
                                </Form>
                            </div>
                        }
                    )
                } else {
                    cx.render(
                        html! {
                            <a href={LOGIN}>"Login"</a>
                        }
                    )
                }
            }
        </nav>
    })
}

#[inline_props]
fn Button<'a>(
    cx: Scope,
    onclick: EventHandler<'a, MouseEvent>,
    children: Element<'a>,
) -> Element<'a> {
    cx.render(html! {
        <button onclick={move |event| onclick.call(event) }>
            {&cx.props.children}
        </button>
    })
}

#[inline_props]
fn TextField<'a>(
    cx: Scope,
    name: &'a str,
    autofocus: Option<bool>,
    placeholder: Option<&'a str>,
) -> Element<'a> {
    let autofocus_attr = if let Some(_) = *autofocus {
        "autofocus"
    } else {
        ""
    };
    let place_holder = if let Some(p) = *placeholder { p } else { "" };
    return cx.render(html! {
        <input  r#type="text"  name="{name}"  autofocus="{autofocus_attr}"  placeholder="{place_holder}" class="bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full" />
    });
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let database_url = env::var("DATABASE_URL")?;
    let pool = make_db_pool(&database_url).await;
    DB_POOL.set(pool).unwrap();
    sqlx::migrate!().run(db()).await?;
    let addr: SocketAddr = ([127, 0, 0, 1], 9001).into();
    let router = routes();

    println!("Listening on {}", addr);

    Server::new(TcpListener::bind(addr)).serve(router).await;

    return Ok(());
}

#[handler]
async fn app_handler(depot: &mut Depot, res: &mut Response) {
    let addr = env::var("SERVER_ADDR").unwrap();
    let glue = dioxus_liveview::interpreter_glue(&format!("ws://{}/ws", addr));
    let user_id: Option<i64> = depot.session().unwrap().get("user_id");
    let user: User = match user_id {
        Some(id) => sqlx::query_as!(User, "select * from users where id = ?", id)
            .fetch_one(db())
            .await
            .unwrap(),
        None => User::default(),
    };
    let new_token = depot.csrf_token().map(|s| &**s).unwrap_or_default();

    res.render(Text::Html(render_lazy(html! {
        <Layout csrf_token={new_token} user={user}>
            <main id="main"></main>
            {glue}
        </Layout>
    })));
}

#[handler]
async fn connect(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), StatusError> {
    let addr = format!("http://{}", env::var("SERVER_ADDR").unwrap());
    let origin = match req.header::<String>(ORIGIN) {
        Some(o) => o,
        None => String::default(),
    };
    if addr != origin {
        return Err(salvo::http::StatusError::not_found());
    }
    let maybe_user_id: Option<i64> = depot.session().unwrap().get("user_id");
    if let Some(user_id) = maybe_user_id {
        let user = sqlx::query_as!(User, "select * from users where id = ?", user_id)
            .fetch_one(db())
            .await
            .unwrap();
        let view = depot.obtain::<Arc<LiveViewPool>>().unwrap().clone();

        // TODO: check the origin as well
        WebSocketUpgrade::new()
            .upgrade(req, res, |ws| async move {
                _ = view
                    .launch_with_props::<AppProps>(
                        dioxus_liveview::salvo_socket(ws),
                        app,
                        AppProps { user },
                    )
                    .await
            })
            .await
    } else {
        return Err(salvo::http::StatusError::not_found());
    }
}
