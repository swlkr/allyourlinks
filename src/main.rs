#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]

use anyhow::Result;
use dioxus::html::input_data::keyboard_types::Code;
use dioxus::prelude::*;
use dioxus_free_icons::icons::bs_icons::*;
use dioxus_free_icons::Icon;
use dioxus_html_macro::html;
use dioxus_liveview::LiveViewPool;
use dioxus_ssr::render_lazy;
use once_cell::sync::{Lazy, OnceCell};
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
use sqlx::sqlite::SqliteJournalMode;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::sqlite::SqliteSynchronous;
use sqlx::sqlite::{SqliteConnectOptions, SqliteQueryResult};
use sqlx::SqlitePool;
use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, Level};

const HOME: &str = "/";
const LOGIN: &str = "/login";
const LOGOUT: &str = "/logout";
const PROFILE: &str = "/profile";
const PUBLIC_PROFILE: &str = "/@<username>";

#[derive(RustEmbed)]
#[folder = "static"]
struct Assets;

#[derive(Debug, Default)]
enum Icon {
    Twitch,
    Twitter,
    Instagram,
    Youtube,
    Tiktok,
    Discord,
    Github,
    Stackoverflow,
    #[default]
    Globe,
}

pub static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();
static DEFAULT_LINKS: Lazy<Vec<Link>> = Lazy::new(|| Link::default_links());

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

fn at(path: &str) -> salvo::Router {
    Router::with_path(path)
}

#[handler]
async fn auth(depot: &mut Depot) -> Result<(), salvo::http::StatusError> {
    let maybe_user = depot.obtain::<User>();
    if let None = maybe_user {
        return Err(salvo::http::StatusError::not_found());
    }
    return Ok(());
}

#[handler]
async fn set_user(depot: &mut Depot) {
    let maybe_id: Option<i64> = depot.session().unwrap().get("user_id");
    if let Some(id) = maybe_id {
        let user = sqlx::query_as!(User, "select id, username, login_code, updated_at, created_at, bio, photo from users where id = ?", id)
            .fetch_one(db())
            .await
            .unwrap();
        depot.inject(user);
    }
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
    let csrf_handler = aes_gcm_session_csrf(csrf_key, form_finder);
    let view = LiveViewPool::new();
    let arc_view = Arc::new(view);

    return Router::new()
        .push(
            Router::new()
                .hoop(session_handler)
                .hoop(csrf_handler)
                .hoop(set_user)
                .push(
                    Router::new()
                        .get(home)
                        .post(signup)
                        .push(at(LOGIN).get(get_login).post(post_login))
                        .push(at(PUBLIC_PROFILE).get(public_profile))
                        .push(at(LOGOUT).post(logout)),
                )
                .push(
                    Router::new()
                        .hoop(auth)
                        .hoop(affix::inject(arc_view))
                        .push(at(PROFILE).get(profile))
                        .push(at("/ws").get(connect)),
                ),
        )
        .push(at("<**path>").get(static_embed::<Assets>()));
}

#[inline_props]
fn Form<'a>(cx: Scope, action: &'a str, children: Element<'a>) -> Element<'a> {
    let app_state = use_shared_state::<AppState>(cx);
    let csrf_token = match app_state {
        Some(st) => st.read().csrf_token.clone(),
        _ => String::with_capacity(0),
    };
    let method = Method::POST;
    cx.render(rsx! (
        form {
            method: "{method}",
            action: "{action}",
            input {
                r#type: "hidden",
                name: "csrf_token",
                value: "{csrf_token}"
            }
            &cx.props.children
        }
    ))
}

#[derive(PartialEq, Props)]
struct AppProps {
    csrf_token: String,
    current_user: User,
}

#[derive(Default, PartialEq)]
struct AppState {
    csrf_token: String,
    current_user: Option<User>,
}

#[derive(Props, Debug)]
struct LayoutProps<'a> {
    csrf_token: &'a str,
    #[props(!optional)]
    current_user: Option<&'a User>,
    #[props(optional)]
    liveview_js: Option<String>,
    children: Element<'a>,
}

impl<'a> LayoutProps<'a> {
    pub async fn from_depot(depot: &mut Depot) -> LayoutProps {
        let addr = env::var("SERVER_ADDR").unwrap();
        let current_user = depot.obtain::<User>();
        let user_id = match &current_user {
            Some(u) => Some(u.id),
            _ => None,
        };
        let liveview_js = match &current_user {
            Some(User { username, .. }) => Some(dioxus_liveview::interpreter_glue(&format!(
                "ws://{}/ws?username={}",
                addr, username
            ))),
            _ => None,
        };
        let csrf_token = depot.csrf_token().map(|s| &**s).unwrap_or_default();

        return LayoutProps {
            csrf_token,
            current_user,
            liveview_js,
            children: Element::default(),
        };
    }
}

fn Layout<'a>(cx: Scope<'a, LayoutProps<'a>>) -> Element<'a> {
    use_shared_state_provider(cx, || AppState {
        csrf_token: cx.props.csrf_token.to_owned(),
        current_user: cx.props.current_user.cloned(),
    });
    let liveview_js = match &cx.props.liveview_js {
        Some(js) => js.clone(),
        None => String::with_capacity(0),
    };
    cx.render(
        rsx! {
            "<!DOCTYPE html>"
            "<html lang=en>"
                head {
                    title {
                      "all your links"  
                    }
                    meta { charset: "utf-8" }
                    meta { name: "viewport", content:"width=device-width" }
                    link { rel: "stylesheet", href: "/output.css" }
                    style { "#main {{ height: calc(100vh - 88px); }}" }
                }
                body {
                    class: "dark:bg-zinc-900 dark:text-yellow-400 bg-yellow-400 text-zinc-900 font-sans max-w-3xl mx-auto",
                    Nav { user: cx.props.current_user }
                    &cx.props.children
                    "{liveview_js}"
                }
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
    cx.render(rsx! {
        header {
            class: "flex flex-col gap-1 text-center",
            h1 {
                class: "font-bold text-5xl lg:text-7xl",
                a {
                    href: HOME,
                    "all your links"
                }
            }
            p {
                class: "max-w-md mx-auto",
                "Share everything you create, sell or curate behind one link"
            }
        }
    })
}

#[inline_props]
fn Home(cx: Scope, error: Option<CreateUserError>) -> Element {
    let err = match error {
        Some(err) => err.to_string(),
        None => String::default(),
    };
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-16 px-4 lg:px-0",
            Header {}
            Form {
                action: "/"
                div {
                    class: "flex flex-col gap-2 md:max-w-lg md:mx-auto",
                    div {
                        class: "flex flex-col",
                        div {
                            class: "dark:text-white text-black",
                            err
                        }
                        TextField {
                            name :"username"
                            autofocus: true
                        }
                    }
                    Cta {
                        "Claim your username"
                    }
                }
            }
            IconList {}
        }
    })
}

#[handler]
async fn home(depot: &mut Depot) -> Text<String> {
    let LayoutProps {
        csrf_token,
        current_user,
        ..
    } = LayoutProps::from_depot(depot).await;
    Text::Html(render_lazy(rsx! {
        Layout {
            csrf_token: csrf_token,
            current_user: current_user,
            Home {}
        }
    }))
}

#[derive(Default, Debug, PartialEq, Clone)]
struct User {
    id: i64,
    username: String,
    login_code: String,
    updated_at: Option<i64>,
    created_at: i64,
    bio: Option<String>,
    photo: Option<String>,
}

impl User {
    async fn by_id(id: i64) -> Result<User, sqlx::Error> {
        return sqlx::query_as!(User, "select id as 'id!', username, login_code, updated_at, created_at, bio, photo from users where id = ?", id)
            .fetch_one(db())
            .await;
    }

    async fn by_username(username: String) -> Result<User, sqlx::Error> {
        return sqlx::query_as!(User, "select id as 'id!', username, login_code, updated_at, created_at, bio, photo from users where username = ?", username)
            .fetch_one(db())
            .await;
    }

    async fn by_login_code(login_code: String) -> Result<User, sqlx::Error> {
        return sqlx::query_as!(User, "select id as 'id!', username, login_code, updated_at, created_at, bio, photo from users where login_code = ?", login_code)
            .fetch_one(db())
            .await;
    }
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
        return User::by_id(id).await;
    }
}

#[handler]
async fn signup(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<()> {
    let new_user: NewUser = req.parse_form().await?;
    let user: User = new_user.insert().await?;
    // make links for every social icon on the home page
    // 3 pieces of data
    // 1. the name of the website
    // 2. the url
    // 3. icon itself
    let links = Link::default_links();
    for mut link in links {
        link.url = format!("{}{}", link.url, user.username);
        link.user_id = user.id;
        let _ = link.create().await;
    }
    let session = depot.session_mut().unwrap();
    _ = session.insert("user_id", user.id)?;
    res.render(Redirect::other(format!("/@{}", user.username)));
    return Ok(());
}

#[inline_props]
fn Login<'a>(cx: Scope, message: Option<&'a str>) -> Element<'a> {
    cx.render(html! {
        <div class="flex flex-col gap-16">
            <Header />
            <Form action="/login">
                <div class="flex flex-col gap-2 md:max-w-lg md:mx-auto">
                    <div class="flex flex-col">
                        <div class="dark:text-white text-black">{*message}</div>
                        <TextField name="login_code" autofocus={true} />
                    </div>
                    <Cta>"Login"</Cta>
                </div>
            </Form>
        </div>
    })
}

#[handler]
async fn get_login(depot: &mut Depot) -> Text<String> {
    let LayoutProps {
        csrf_token,
        current_user,
        ..
    } = LayoutProps::from_depot(depot).await;
    Text::Html(render_lazy(rsx! {
        Layout {
            csrf_token: csrf_token,
            current_user: current_user,
            Login {}
        }
    }))
}

#[derive(Deserialize, PartialEq, Clone, Debug, Default)]
struct Link {
    id: i64,
    user_id: i64,
    url: String,
    name: Option<String>,
    updated_at: Option<i64>,
    created_at: i64,
}

impl Link {
    async fn all_by_user_id(user_id: i64) -> Vec<Link> {
        return sqlx::query_as!(
            Link,
            "select id as 'id!', user_id, url, name, updated_at, created_at from links where user_id = ? order by created_at desc",
            user_id
        )
        .fetch_all(db())
        .await
        .unwrap();
    }

    async fn last() -> Option<Link> {
        sqlx::query_as!(Link, "select id as 'id!', user_id as 'user_id!', url as 'url!', name, updated_at, created_at as 'created_at!' from links order by created_at asc limit 1")
            .fetch_one(db())
            .await
            .ok()
    }

    async fn delete(&self) -> Result<SqliteQueryResult, sqlx::Error> {
        sqlx::query!("delete from links where id = ?", self.id)
            .execute(db())
            .await
    }

    async fn insert<'a>(user_id: i64, url: &'a str) -> Result<SqliteQueryResult, sqlx::Error> {
        sqlx::query!(
            "insert into links (user_id, url) values (?, ?)",
            user_id,
            url
        )
        .execute(db())
        .await
    }

    async fn create(&self) -> Result<SqliteQueryResult, sqlx::Error> {
        let name = if let Some(n) = &self.name {
            n.to_owned()
        } else {
            String::default()
        };
        sqlx::query!(
            "insert into links (user_id, url, name) values (?, ?, ?)",
            self.user_id,
            self.url,
            self.name
        )
        .execute(db())
        .await
    }

    async fn find_by_id(id: i64) -> Option<Link> {
        sqlx::query_as!(Link, "select * from links where id = ?", id,)
            .fetch_one(db())
            .await
            .ok()
    }

    async fn update(&self) -> Result<Link, sqlx::Error> {
        sqlx::query_as!(
            Link,
            "update links set name = ?, url = ?, updated_at = unixepoch() where id = ? returning id as 'id!', user_id as 'user_id!', url as 'url!', name, updated_at, created_at as 'created_at!'",
            self.name,
            self.url,
            self.id
        ).fetch_one(db()).await
    }

    fn parse_name(name_and_url: &String) -> Option<String> {
        let start = name_and_url.find('[');
        let end = name_and_url.find(']');
        match (start, end) {
            (Some(first), Some(last)) => Some((&name_and_url)[(first + 1)..last].to_owned()),
            _ => None,
        }
    }

    fn parse_url(name_and_url: &String) -> String {
        let start = name_and_url.find('(');
        let end = name_and_url.find(')');
        match (start, end) {
            (Some(first), Some(last)) => (&name_and_url)[(first + 1)..last].to_owned(),
            _ => String::default(),
        }
    }

    fn new(url: &str, name: &str) -> Self {
        Link {
            url: url.to_owned(),
            name: Some(name.to_owned()),
            id: 0,
            user_id: 0,
            updated_at: None,
            created_at: 0,
        }
    }

    fn icon(&self) -> Icon {
        if self.url.contains("twitter.com") {
            Icon::Twitter
        } else if self.url.contains("twitch.tv") {
            Icon::Twitch
        } else {
            Icon::Globe
        }
    }

    fn url_from_icon(icon: Icon) -> String {
        let s = match icon {
            Icon::Twitch => "https://twitch.tv/",
            Icon::Twitter => "https://twitter.com/",
            Icon::Instagram => "https://instagram.com/",
            Icon::Youtube => "https://youtube.com/",
            Icon::Tiktok => "https://tiktok.com/",
            Icon::Discord => "https://discord.com/",
            Icon::Github => "https://github.com/",
            Icon::Stackoverflow => "https://stackoverflow.com/",
            Icon::Globe => "",
        };
        return s.to_string();
    }

    fn default_links() -> Vec<Link> {
        vec![
            Link::new("twitch.tv/", "twitch"),
            Link::new("twitter.com/", "twitter"),
            Link::new("instagram.com/", "instagram"),
            Link::new("youtube.com/", "youtube"),
            Link::new("tiktok.com/", "tiktok"),
            Link::new("discord.com/", "discord"),
            Link::new("github.com/", "github"),
            Link::new("stackoverflow.com/", "stackoverflow"),
        ]
    }
}

#[inline_props]
fn LinkIconComponent<'a>(cx: Scope, name_and_url: &'a String) -> Element<'a> {
    cx.render(rsx!(if name_and_url.contains("twitter.com") {
        rsx! {
            Icon {
                width: 32,
                height: 32,
                icon: BsTwitter
            }
        }
    } else if name_and_url.contains("twitch.tv") {
        rsx! {
            Icon {
                width: 32,
                height: 32,
                icon: BsTwitch
            }
        }
    } else {
        rsx! {
            Icon {
                width: 32,
                height: 32,
                icon: BsGlobe,
            }
        }
    }))
}

#[inline_props]
fn LinkComponent<'a>(
    cx: Scope,
    link: Link,
    is_deleting: &'a bool,
    on_delete: EventHandler<'a, &'a Link>,
) -> Element {
    let link_name = match &link.name {
        Some(n) => n,
        None => &link.url,
    };
    let name_and_url = use_state(cx, || format!("[{}]({})", link_name, link.url));
    let is_editing = use_state(cx, || false);
    let edit_clicked = move || {
        is_editing.set(true);
    };
    let link_state = use_state(cx, || link.clone());
    let id = link.id;
    let on_enter = move || {
        to_owned![name_and_url, is_editing, link_state];
        cx.spawn(async move {
            if let Some(mut l) = Link::find_by_id(id).await {
                l.name = Link::parse_name(name_and_url.get());
                l.url = Link::parse_url(name_and_url.get());
                match l.update().await {
                    Ok(link) => {
                        link_state.set(link);
                        is_editing.set(false);
                    }
                    _ => (),
                }
            }
        });
    };
    let on_escape = move || {
        is_editing.set(false);
    };
    let url = &link_state.get().url;
    let name = &link_state.get().name;
    cx.render(if *is_editing.get() {
        rsx! {
            div {
                class: "flex gap-4",
                LinkIconComponent {
                    name_and_url: name_and_url.get()
                },
                TextField {
                    name: "name_and_url",
                    autofocus: true,
                    value: "{name_and_url}",
                    oninput: move |event: Event<FormData>| {
                        let val = event.value.clone();
                        name_and_url.set(val);
                    },
                    onblur: move |_: Event<FocusData>| {
                        is_editing.set(false);
                    },
                    onkeypress: move |event: Event<KeyboardData>| {
                        match event.code() {
                            Code::Enter => {
                                on_enter();
                            },
                            Code::Escape => {
                                on_escape();
                            },
                            _ => {}
                        }
                    }
                }
            }
        }
    } else {
        rsx! {
            div {
                class: "flex gap-4 items-center",
                LinkIconComponent {
                    name_and_url: name_and_url.get()
                }
                a {
                    class: "px-2 py-3 dark:bg-yellow-400 dark:text-zinc-900 rounded-md",
                    href: "{url}",
                    onclick: move |event| {
                        event.stop_propagation();
                        edit_clicked()
                    },
                    if let Some(n) = name {
                        rsx! {
                            "{n}"
                        }
                    } else {
                        rsx! {
                            "{url}"
                        }
                    }
                }
                if **is_deleting {
                    rsx!(
                        DeleteButton {
                            onclick: move |event| on_delete.call(link)
                        }
                    )
                }
            }
        }
    })
}

#[inline_props]
fn DeleteButton<'a>(cx: Scope, onclick: EventHandler<'a, MouseEvent>) -> Element<'a> {
    cx.render(rsx!(CircleButton {
        onclick: move |event| onclick.call(event),
        disabled: false,
        div {
            class: "bg-zinc-900 dark:bg-yellow-400 flex justify-center items-center -my-3",
            Icon {
                width: 40,
                height: 40,
                icon: BsX
            }
        }
    }))
}

#[inline_props]
fn LinkList<'a>(
    cx: Scope,
    links: Option<Vec<Link>>,
    is_deleting: bool,
    on_delete: EventHandler<'a, &'a Link>,
) -> Element {
    if links.is_none() {
        return None;
    }
    cx.render(rsx!(
        div {
            class: "flex flex-col gap-8 items-start h-full",
            links.clone().unwrap().into_iter().map(|link| {
                rsx! {
                   LinkComponent {
                        key: "{link.id}",
                        link: link,
                        is_deleting: is_deleting,
                        on_delete: move |link| on_delete.call(link)
                   }
                }
            })
        }
    ))
}

#[derive(Props, PartialEq)]
struct ProfileProps<'a> {
    #[props(!optional)]
    current_user: Option<&'a User>,
}

fn Profile<'a>(cx: Scope<'a, ProfileProps<'a>>) -> Element<'a> {
    let loading = use_state(cx, || false);
    let User {
        photo,
        username,
        bio,
        id,
        ..
    } = cx.props.current_user.unwrap();
    let links_future = use_future(cx, (loading,), |_| {
        to_owned![id];
        async move { Link::all_by_user_id(id).await }
    });
    let links = links_future.value().unwrap().clone();
    let add_link = move || {
        to_owned![loading, id];
        cx.spawn(async move {
            let _ = Link::insert(id, "https://example.com").await.unwrap();
            loading.set(false);
        });
    };
    let delete_last_link = move || {
        to_owned![loading, id];
        cx.spawn(async move {
            if let Some(link) = Link::last().await {
                let _ = link.delete().await;
                loading.set(false);
            }
        });
    };
    let bio = match bio {
        Some(b) => b.clone(),
        _ => String::with_capacity(0),
    };
    let add_link_clicked = use_state(cx, || false);
    let is_deleting = use_state(cx, || false);
    let on_add_link_click = move || {
        add_link_clicked.set(!add_link_clicked);
    };
    let on_delete_link_click = move || {
        is_deleting.set(!is_deleting);
    };
    let on_delete = move |link: &Link| {
        to_owned![loading, link];
        cx.spawn(async move {
            let _ = link.delete().await;
            loading.set(false);
        });
    };
    cx.render(rsx! {
        if *add_link_clicked.get() {
            rsx! (
                AddLinkModal {
                    on_close: move |_| {
                        on_add_link_click();
                        links_future.restart();
                    }
                }
            )
        }
        div {
            class: "flex flex-col max-w-3xl mx-auto gap-8 text-center items-center h-full relative w-full mb-24 mt-8 relative",
            {
                match photo {
                    Some(p) => rsx! {
                        img { src: "{p}" }
                    },
                    _ => rsx! { Icon {
                        width: 64,
                        height: 64,
                        icon: BsPersonCircle
                    }}
                }
            }
            div {
                class: "font-bold text-xl",
                "Editing @{username}"
            }
            div { bio }
            LinkList {
                links: links,
                is_deleting: *is_deleting.get(),
                on_delete: move |link| { loading.set(true); on_delete(link); },
            }
            div {
                class: "fixed right-2 bottom-2",
                AddLinkButton {
                    onclick: move |_| on_add_link_click(),
                }
                DeleteLinkButton {
                    onclick: move |_| on_delete_link_click(),
                }
            }
        }
    })
}

#[derive(Deserialize)]
struct LoginUser {
    login_code: String,
}

#[handler]
async fn post_login(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<()> {
    let login_user: LoginUser = req.parse_form().await?;
    let maybe_user: Option<User> = User::by_login_code(login_user.login_code).await.ok();
    let session = depot.session_mut().unwrap();
    if let Some(u) = maybe_user {
        session.insert("user_id", u.id).unwrap();
        res.render(Redirect::other(PROFILE));
    } else {
        // TODO exponential backoff
        let LayoutProps {
            csrf_token,
            current_user,
            ..
        } = LayoutProps::from_depot(depot).await;
        res.render(Text::Html(render_lazy(rsx! {
            Layout {
                csrf_token: csrf_token,
                current_user: current_user,
                Login {
                    message: "Invalid login code"
                }
            }
        })));
    }
    return Ok(());
}

#[handler]
fn logout(depot: &mut Depot, res: &mut Response) {
    let session = depot.session_mut().unwrap();
    session.remove("user_id");
    res.render(Redirect::other(HOME));
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

#[derive(Props)]
struct IconListProps<'a> {
    #[props(optional)]
    onclick: Option<EventHandler<'a, Icon>>,
}

fn IconList<'a>(cx: Scope<'a, IconListProps<'a>>) -> Element {
    let on_click = |icon: Icon| {
        if let Some(click) = cx.props.onclick.as_ref() {
            click.call(icon);
        }
    };
    cx.render(rsx!(
        div {
            class: "grid grid-cols-4 gap-8 md:mx-auto",
            button {
                onclick: move |_| on_click(Icon::Github),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsGithub
                }
            }
            button {
                onclick: move |_| on_click(Icon::Twitter),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsTwitter
                }
            },
            button {
                onclick: move |_| on_click(Icon::Discord),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsDiscord
                }
            },
            button {
                onclick: move |_| on_click(Icon::Tiktok),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsTiktok
                }
            },
            button {
                onclick: move |_| on_click(Icon::Twitch),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsTwitch
                }
            },
            button {
                onclick: move |_| on_click(Icon::Youtube),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsYoutube
                }
            },
            button {
                onclick: move |_| on_click(Icon::Stackoverflow),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsStackOverflow
                }
            },
            button {
                onclick: move |_| on_click(Icon::Instagram),
                Icon {
                    width: 32,
                    height: 32,
                    icon: BsInstagram
                }
            },
        }
    ))
}

#[inline_props]
fn AddLinkModal<'a>(cx: Scope, on_close: EventHandler<'a, ()>) -> Element<'a> {
    let app_state = use_shared_state::<AppState>(cx);
    let current_user = app_state.unwrap().read().current_user.clone().unwrap();
    let username = use_state(cx, || current_user.username);
    let user_id = current_user.id;
    let mut step = use_state(cx, || 0);
    let url = use_state(cx, || String::new());
    let name = use_state(cx, || String::new());
    let on_icon_click = move |icon: Icon| {
        to_owned![step, url];
        let new_url = Link::url_from_icon(icon);
        url.set(new_url);
        step += 1;
    };
    let mut on_enter = move || step += 1;
    let on_escape = move || {};
    let mut on_next = move || {
        name.set(format!("{}{}", url, username));
        url.set(format!("{}{}", url, username));
        step += 1;
    };
    let on_save = move || {
        to_owned![step, url, name];

        cx.spawn(async move {
            let mut link = Link::new(url.get(), name.get());
            link.user_id = user_id;
            let _ = link.create().await;
            step += 1;
        });
    };
    if *step.get() == 3 {
        cx.props.on_close.call(());
        return None;
    }
    cx.render(rsx!(div {
        class: "max-w-3xl w-3/4 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 p-6 bg-yellow-400 text-zinc-900 dark:bg-zinc-800 dark:text-yellow-400 z-20",
        {
            match *step.get() {
                0 => rsx!(
                    div {
                        class: "flex flex-col gap-4",
                        h1 {
                            class: "text-2xl lg:text-4xl text-center",
                            "Add a link"
                        }
                        IconList {
                            onclick: move |icon| on_icon_click(icon)
                        }
                    }
                ),
                1 => rsx!(
                    div {
                        class: "flex flex-col gap-4",
                        h1 {
                            class: "text-2xl lg:text-4xl text-center",
                            "Enter username"
                        }
                        TextField {
                            name: "username",
                            autofocus: true,
                            value: "{username}",
                            oninput: move |event: Event<FormData>| {
                                let val = event.value.clone();
                                username.set(val);
                            },
                            onkeypress: move |event: Event<KeyboardData>| {
                                match event.code() {
                                    Code::Enter => {
                                        on_enter();
                                    },
                                    Code::Escape => {
                                        on_escape();
                                    },
                                    _ => {}
                                }
                            }
                        }
                        Button {
                            onclick: move |_| on_next(),
                            "Next"
                        }
                    }
                ),
                2 => rsx!(
                    div {
                        class: "flex flex-col gap-4",
                        h1 {
                            class: "text-2xl lg:text-4xl text-center",
                            "Change link name"
                        }
                        TextField {
                            name: "name",
                            value: "{name}",
                            oninput: move |event: Event<FormData>| {
                                let val = event.value.clone();
                                name.set(val);
                            }
                        }
                        Button {
                            onclick: move |_| on_save(),
                            "Save"
                        }
                    }
                ),
                _ => rsx!(div{})
            }
        }
    }))
}

#[derive(Props, PartialEq)]
struct NavProps<'a> {
    #[props(!optional)]
    user: Option<&'a User>,
}

fn Nav<'a>(cx: Scope<'a, NavProps<'a>>) -> Element<'a> {
    cx.render(rsx! {
        nav {
            class: "gap-8 justify-center py-8 hidden md:flex",
            a {
                href: HOME,
                "Home"
            }
            {
                match &cx.props.user {
                    Some(_) => {
                        rsx! {
                            div {
                                class: "flex gap-8",
                                a {
                                    href: PROFILE,
                                    "Profile"
                                }
                                Form {
                                    action: LOGOUT,
                                    Submit {
                                        value: "Logout"
                                    }
                                }
                            }
                        }
                    },
                    _ => rsx! {
                        a {
                            href: LOGIN,
                            "Login"
                        }
                    }
                }
            }
        }
        nav {
            class: "flex md:hidden lg:hidden justify-between items-center fixed bottom-0 left-0 right-0 z-10",
            NavButton {
                a {
                    href: HOME,
                    class: "flex flex-col justify-center items-center",
                    Icon {
                        width: 16,
                        height: 16,
                        icon: BsHouseFill
                    }
                    div {
                        "Home" 
                    }
                }
            }
            NavButton {
                a {
                    href: PROFILE,
                    class: "flex flex-col justify-center items-center",
                    Icon {
                        width: 16,
                        height: 16,
                        icon: BsPersonCircle
                    }
                    div {
                        "Profile"
                    }
                }
            }
            NavButton {
                Form {
                    action: LOGOUT,
                    button {
                        class: "flex flex-col justify-center items-center",
                        r#type: "submit",
                        Icon {
                            width: 16,
                            height: 16,
                            icon: BsDoorOpenFill
                        }
                        div {
                            "Logout"
                        }
                    }
                }
            }
        }
    })
}

#[inline_props]
fn NavButton<'a>(cx: Scope, children: Element<'a>) -> Element<'a> {
    cx.render(rsx!(div {
        class: "bg-zinc-700 text-yellow-400 py-4 flex flex-auto text-center justify-center",
        &cx.props.children
    }))
}

#[inline_props]
fn Button<'a>(
    cx: Scope,
    onclick: EventHandler<'a, MouseEvent>,
    children: Element<'a>,
) -> Element<'a> {
    cx.render(rsx! {
        button {
            onclick: move |event| onclick.call(event),
            &cx.props.children
        }
    })
}

#[inline_props]
fn CircleButton<'a>(
    cx: Scope,
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
    children: Element<'a>,
) -> Element<'a> {
    let is_disabled = match disabled {
        Some(true) => true,
        Some(false) => false,
        _ => false,
    };
    let disabled_str = match is_disabled {
        true => "",
        false => "false",
    };
    let on_click = move |event| {
        if !is_disabled {
            onclick.call(event)
        }
    };
    cx.render(rsx! {
        button {
            class: "rounded-full dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 p-3 w-12 h-12 disabled:opacity-50",
            disabled: "{disabled_str}",
            onclick: on_click,
            &cx.props.children
        }
    })
}

#[inline_props]
fn AddLinkButton<'a>(
    cx: Scope,
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
    children: Element<'a>,
) -> Element<'a> {
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-2 items-center",
            CircleButton {
                onclick: move |event| { onclick.call(event) },
                disabled: disabled.unwrap_or(false),
                div {
                    class: "bg-zinc-900 dark:bg-yellow-400 flex justify-center items-center -my-3",
                    Icon { width: 40, height: 40, icon: BsPlus }
                }
            }
            div { "Add" }
        }
    })
}

#[inline_props]
fn DeleteLinkButton<'a>(
    cx: Scope,
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
    children: Element<'a>,
) -> Element<'a> {
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-2 items-center",
            CircleButton {
                onclick: move |event| { onclick.call(event) },
                disabled: disabled.unwrap_or(false),
                div {
                    class: "bg-zinc-900 dark:bg-yellow-400 flex justify-center items-center -my-3",
                    Icon { width: 40, height: 40, icon: BsX }
                }
            }
            div { "Delete" }
        }
    })
}

#[inline_props]
fn TextField<'a>(
    cx: Scope,
    name: &'a str,
    lbl: Option<&'a str>,
    autofocus: Option<bool>,
    value: Option<&'a str>,
    onblur: Option<EventHandler<'a, Event<FocusData>>>,
    onkeypress: Option<EventHandler<'a, KeyboardEvent>>,
    oninput: Option<EventHandler<'a, Event<FormData>>>,
    placeholder: Option<&'a str>,
) -> Element<'a> {
    let autofocus_attr = if let Some(_) = *autofocus {
        "autofocus"
    } else {
        ""
    };
    let place_holder = if let Some(p) = *placeholder { p } else { "" };
    let val = if let Some(val) = value { val } else { "" };
    let label_ = if let Some(label_) = lbl { label_ } else { "" };
    return cx.render(rsx! (
        label {
            class: "flex flex-col gap-2",
            "{label_}"
            input {
                r#type: "text",
                name: "{name}",
                autofocus: "{autofocus_attr}",
                placeholder: "{place_holder}",
                class: "bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full",
                value: "{val}",
                onkeypress: |event| {
                    if let Some(kp) = onkeypress.as_ref() {
                        kp.call(event);
                    }
                },
                oninput: |event| {
                    if let Some(inp) = oninput.as_ref() {
                        inp.call(event);
                    }
                },
                onblur: |event| {
                    if let Some(ev) = onblur.as_ref() {
                        ev.call(event)
                    }
                }
            }
        }
    ));
}

fn app(cx: Scope<AppProps>) -> Element {
    let AppProps {
        csrf_token,
        current_user,
        ..
    } = cx.props;
    use_shared_state_provider(cx, || AppState {
        csrf_token: csrf_token.to_owned(),
        current_user: Some(current_user.clone()),
    });
    return cx.render(rsx! {
        Profile { current_user: Some(current_user) }
    });
}

#[derive(Deserialize)]
struct ProfileParams {
    username: String,
}

#[handler]
async fn public_profile(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), StatusError> {
    let params: ProfileParams = req.parse_params().unwrap();
    let user_result = User::by_username(params.username).await;
    let user = match user_result {
        Ok(u) => u,
        Err(_) => return Err(StatusError::not_found()),
    };
    let User {
        photo,
        username,
        bio,
        id,
        ..
    } = user;
    let links = Link::all_by_user_id(id).await;
    let props = LayoutProps::from_depot(depot).await;
    res.render(Text::Html(render_lazy(rsx! (
        Layout {
            csrf_token: props.csrf_token,
            current_user: props.current_user,
            div {
                class: "flex flex-col max-w-3xl mx-auto gap-8 text-center items-center h-full relative w-full",
                {
                    match photo {
                        Some(p) => rsx! {
                            img { src: "{p}" }
                        },
                        _ => rsx! { Icon {
                            width: 64,
                            height: 64,
                            icon: BsPersonCircle
                        }}
                    }
                }
                div {
                    class: "font-bold text-xl",
                    "@{username}"
                }
                div {
                    "{bio:?}"
                }
                LinkList {
                    links: links,
                    is_deleting: false,
                    on_delete: move |_| (),
                }
        }
    }))));
    return Ok(());
}

#[handler]
async fn profile(res: &mut Response, depot: &mut Depot) -> Result<(), StatusError> {
    let LayoutProps {
        current_user,
        csrf_token,
        liveview_js,
        ..
    } = LayoutProps::from_depot(depot).await;
    res.render(Text::Html(render_lazy(rsx! (
        Layout {
            csrf_token: csrf_token,
            current_user: current_user,
            liveview_js: liveview_js.unwrap(),
            div { id: "main" },
        }
    ))));
    return Ok(());
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
    let view = depot.obtain::<Arc<LiveViewPool>>().unwrap().clone();
    let maybe_user = depot.obtain::<User>().cloned();
    let liveview_js = match &maybe_user {
        Some(User { username, .. }) => Some(dioxus_liveview::interpreter_glue(&format!(
            "ws://{}/ws?username={}",
            addr, username
        ))),
        _ => None,
    };
    let csrf_token = depot
        .csrf_token()
        .map(|s| &**s)
        .unwrap_or_default()
        .to_string();

    if let Some(current_user) = maybe_user {
        WebSocketUpgrade::new()
            .upgrade(req, res, |ws| async move {
                _ = view
                    .launch_with_props::<AppProps>(
                        dioxus_liveview::salvo_socket(ws),
                        app,
                        AppProps {
                            csrf_token,
                            current_user,
                        },
                    )
                    .await
            })
            .await
    } else {
        return Err(salvo::http::StatusError::not_found());
    }
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
