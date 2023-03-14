#![allow(non_snake_case)]

mod database;

use anyhow::Result;
use database::db;
use dioxus::prelude::*;
use dioxus_elements::input_data::keyboard_types::Key;
use dioxus_free_icons::icons::bs_icons::*;
use dioxus_free_icons::Icon;
use dioxus_html_macro::html;
use dioxus_liveview::LiveViewPool;
use dioxus_ssr::render_lazy;
use fermi::*;
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
use sqlx::sqlite::SqliteQueryResult;
use std::collections::HashSet;
use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::Level;

pub const HOME: &str = "/";
pub const LOGIN: &str = "/login";
pub const LOGOUT: &str = "/logout";
pub const PROFILE: &str = "/profile";
pub const PUBLIC_PROFILE: &str = "/@<username>";

static USER: Atom<User> = |_| User::default();
static SELECTED_LINK_IDS: Atom<HashSet<i64>> = |_| HashSet::new();

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
async fn set_current_user_handler(depot: &mut Depot) {
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
                .hoop(set_current_user_handler)
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

#[derive(Props)]
struct FormProps<'a> {
    action: &'a str,
    children: Element<'a>,
}

fn Form<'a>(cx: Scope<'a, FormProps<'a>>) -> Element {
    let app_state = use_shared_state::<AppState>(cx);
    let csrf_token = match app_state {
        Some(st) => st.read().csrf_token.clone(),
        _ => String::with_capacity(0),
    };
    let method = Method::POST;
    cx.render(rsx! (
        form {
            method: "{method}",
            action: "{cx.props.action}",
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
    links: Vec<Link>,
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
                    // style { "#main {{ height: calc(100vh - 88px); }}" }
                }
                body {
                    class: "dark:bg-zinc-900 dark:text-yellow-400 bg-yellow-400 text-zinc-900 font-sans max-w-3xl mx-auto mb-[150px]",
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

    async fn update(&self) -> Result<User, sqlx::Error> {
        sqlx::query_as!(
            User,
            "update users set bio = ?, updated_at = unixepoch() where id = ? returning id as 'id!', bio, photo, username as 'username!', login_code as 'login_code!', updated_at, created_at as 'created_at!'",
            self.bio,
            self.id
        ).fetch_one(db()).await
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
    async fn delete_by_ids(ids: Vec<i64>) -> Result<SqliteQueryResult, sqlx::Error> {
        let sql = format!(
            "delete from links where id in ({})",
            (0..ids.len()).map(|_| "?").collect::<Vec<&str>>().join(",")
        );
        let mut q = sqlx::query(&sql);
        for id in ids {
            q = q.bind(id);
        }
        return q.execute(db()).await;
    }

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

    async fn insert<'a>(
        user_id: i64,
        url: &'a str,
        name: Option<String>,
    ) -> Result<SqliteQueryResult, sqlx::Error> {
        sqlx::query!(
            "insert into links (user_id, url, name) values (?, ?, ?)",
            user_id,
            url,
            name
        )
        .execute(db())
        .await
    }

    async fn create(&self) -> Result<SqliteQueryResult, sqlx::Error> {
        sqlx::query!(
            "insert into links (user_id, url, name) values (?, ?, ?)",
            self.user_id,
            self.url,
            self.name
        )
        .execute(db())
        .await
    }

    async fn update(id: i64, url: String, name: Option<String>) -> Result<Link, sqlx::Error> {
        sqlx::query_as!(
            Link,
            "update links set name = ?, url = ?, updated_at = unixepoch() where id = ? returning id as 'id!', user_id as 'user_id!', url as 'url!', name, updated_at, created_at as 'created_at!'",
            name,
            url,
            id
        ).fetch_one(db()).await
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
        } else if self.url.contains("github.com") {
            Icon::Github
        } else if self.url.contains("instagram.com") {
            Icon::Instagram
        } else if self.url.contains("youtube.com") {
            Icon::Youtube
        } else if self.url.contains("tiktok.com") {
            Icon::Tiktok
        } else if self.url.contains("discord.com") {
            Icon::Discord
        } else if self.url.contains("stackoverflow.com") {
            Icon::Stackoverflow
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
fn LinkIconComponent<'a>(cx: Scope, link: &'a Link) -> Element<'a> {
    cx.render(match link.icon() {
        Icon::Twitch => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsTwitch
        },),
        Icon::Twitter => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsTwitter
        },),
        Icon::Instagram => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsInstagram
        },),
        Icon::Youtube => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsYoutube
        },),
        Icon::Tiktok => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsTiktok
        },),
        Icon::Discord => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsDiscord
        },),
        Icon::Github => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsGithub
        },),
        Icon::Stackoverflow => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsStackOverflow
        },),
        Icon::Globe => rsx!(Icon {
            width: 32,
            height: 32,
            icon: BsGlobe
        },),
    })
}

#[derive(Props)]
struct DeleteLinkProps<'a> {
    ondelete: EventHandler<'a>,
}

fn DeleteLink<'a>(cx: Scope<'a, DeleteLinkProps<'a>>) -> Element {
    let selected_link_ids: &HashSet<i64> = use_read(cx, SELECTED_LINK_IDS);
    let num_to_delete = selected_link_ids.len();
    let s = match num_to_delete {
        1 => "link",
        _ => "links",
    };
    cx.render(rsx! {
        div {
            class: "flex gap-12 pt-8",
            RoundedRect {
                onclick: move |_| cx.props.ondelete.call(()),
                "Delete ({num_to_delete}) {s}?"
            }
        }
    })
}

#[derive(Props)]
struct SelectButtonProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
}

fn SelectButton<'a>(cx: Scope<'a, SelectButtonProps<'a>>) -> Element {
    let selected = use_state(cx, || false);
    let selected_class = match **selected {
        true => "dark:bg-yellow-400 bg-zinc-900",
        false => "bg-transparent",
    };
    cx.render(rsx! {
        CircleButtonSmall {
            onclick: move |event| { cx.props.onclick.call(event); selected.set(!selected) },
            disabled: false,
            div {
                class: "transition ease-out rounded-full w-3/4 h-3/4 {selected_class}"
            }
        }
    })
}

#[derive(Props)]
struct ShowLinkProps<'a> {
    link: &'a Link,
}

fn ShowLink<'a>(cx: Scope<'a, ShowLinkProps<'a>>) -> Element {
    let selected_links: &HashSet<i64> = use_read(cx, SELECTED_LINK_IDS);
    let set_selected_links = use_set(cx, SELECTED_LINK_IDS);
    let link = cx.props.link;
    let display = match &link.name {
        Some(n) => n,
        None => &link.url,
    };
    let on_select = move |_| {
        to_owned![selected_links, set_selected_links];
        let mut new_links: HashSet<i64> = selected_links;
        if new_links.contains(&link.id) {
            new_links.remove(&link.id);
        } else {
            new_links.insert(link.id);
        }
        set_selected_links(new_links);
    };
    cx.render(
        rsx! {
            div {
                class: "flex gap-4 border-t dark:border-zinc-700 border-zinc-300 p-4 pt-4 w-full items-center",
                SelectButton {
                    onclick: on_select
                }
                LinkIconComponent {
                    link: link
                }
                a {
                    class: "grow",
                    "{display}"
                }
            }
        }
    )
}

#[derive(Props, PartialEq)]
struct LinkListProps {
    links: Vec<Link>,
}

fn LinkList<'a>(cx: Scope<'a, LinkListProps>) -> Element {
    cx.render(rsx! {
        div {
            cx.props.links.iter().map(|link| {
                rsx! {
                    ShowLink {
                        key: "{link.id}",
                        link: link,
                    }
                }
            })
        }
    })
}

fn Bio(cx: Scope) -> Element {
    let user: &User = use_read(cx, USER);
    let set_user = use_set(cx, USER);
    let onenter = move |_| {
        to_owned![set_user, user];
        cx.spawn(async move {
            match user.update().await {
                Ok(user) => {
                    set_user(user);
                }
                _ => (),
            }
        });
    };
    let oninput = move |event: FormEvent| {
        to_owned![user];
        user.bio = Some(event.value.clone());
        set_user(user);
    };
    let bio = match &user.bio {
        Some(b) => b.clone(),
        None => "Add your bio here".to_string(),
    };
    cx.render(rsx! {
        div {
            class: "w-full px-4",
            MultilineTextInput {
                value: bio,
                autofocus: true,
                oninput: oninput,
                onenter: onenter,
            }
        }
    })
}

#[derive(Props)]
struct AddEditLinkProps<'a> {
    onsave: EventHandler<'a, (Option<i64>, String, Option<String>)>,
    #[props(!optional)]
    link: Option<&'a Link>,
}

fn AddEditLink<'a>(cx: Scope<'a, AddEditLinkProps<'a>>) -> Element {
    let (id, url, name) = match cx.props.link {
        Some(link) => (Some(link.id), link.url.clone(), link.name.clone()),
        None => (None, String::default(), None),
    };
    let url = use_state(cx, || url);
    let name = use_state(cx, || name);
    let user = use_read(cx, USER);
    let on_icon_click = move |icon| {
        to_owned![url, user];
        let u = Link::url_from_icon(icon);
        let new_url = format!("{}{}", u, user.username);
        url.set(new_url);
    };
    cx.render(rsx! {
        div {
            div {
                class: "flex flex-col gap-8",
                div {
                    class: "flex flex-col gap-2",
                    div { class: "font-bold", "select a link" }
                    IconList {
                        onclick: on_icon_click
                    }
                }
                div {
                    class: "flex flex-col gap-2",
                    label { r#for: "url", class: "font-bold", "change the url" }
                    TextInput {
                        value: url.get(),
                        oninput: move |event: FormEvent| url.set(event.value.clone()),
                        name: "url"
                    }
                }
                div {
                    class: "flex flex-col gap-2",
                    label { r#for: "name", class: "font-bold", "add a name instead of url" }
                    TextInput {
                        name: "name",
                        value: name.get().as_ref().map_or("", String::as_str),
                        oninput: move |event: FormEvent| name.set(Some(event.value.clone())),
                    }
                }
                RoundedRect {
                    onclick: move |_| cx.props.onsave.call((id, url.get().clone(), name.get().clone())),
                    "Save link"
                }
            }
        }
    })
}

#[derive(PartialEq)]
enum ProfileAction {
    Add,
    Delete,
    Edit,
    None,
}

#[derive(Props, PartialEq)]
struct ProfileProps<'a> {
    user: &'a User,
    links: Vec<Link>,
}

fn Profile<'a>(cx: Scope<'a, ProfileProps<'a>>) -> Element {
    let user = cx.props.user;
    let links = use_state(cx, || cx.props.links.clone());
    let selected_link_ids: &HashSet<i64> = use_read(cx, SELECTED_LINK_IDS);
    let action = use_state(cx, || ProfileAction::None);
    let User {
        photo, username, ..
    } = user;
    let onsave = move |(id, url, name): (Option<i64>, String, Option<String>)| {
        to_owned![user, links, action];
        if url.is_empty() {
            todo!("Show an error or something that url needs to be filled in");
            // action.set(ProfileAction::None);
        } else {
            cx.spawn(async move {
                if let Some(id) = id {
                    let _ = Link::update(id, url, name).await;
                } else {
                    let _ = Link::insert(user.id, &url, name).await;
                }
                let new_links = Link::all_by_user_id(user.id).await;
                links.set(new_links);
                action.set(ProfileAction::None);
            });
        }
    };
    let id = selected_link_ids.iter().map(|x| *x).last();
    let link = if let Some(id) = id {
        links.iter().find(|l| l.id == id)
    } else {
        None
    };
    let ondelete = move |_| {
        if selected_link_ids.is_empty() {
            return;
        }
        to_owned![links, user, selected_link_ids, action];
        cx.spawn(async move {
            let ids: Vec<i64> = selected_link_ids.into_iter().collect();
            let _ = Link::delete_by_ids(ids).await;
            let new_links = Link::all_by_user_id(user.id).await;
            links.set(new_links);
            action.set(ProfileAction::None);
        });
    };
    cx.render(rsx! {
        div {
            class: "flex flex-col max-w-3xl mx-auto gap-8 items-center h-full relative w-full mt-8 relative",
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
            Bio {}
            LinkList {
                links: links.to_vec()
            }
            if **action != ProfileAction::None {
                rsx! {
                    Sheet {
                        onclose: move |_| action.set(ProfileAction::None),
                        match **action {
                            ProfileAction::Add => rsx! { AddEditLink {
                                onsave: onsave,
                                link: None
                            } },
                            ProfileAction::Delete => rsx! { DeleteLink {
                                ondelete: ondelete
                            } },
                            ProfileAction::Edit => rsx! { AddEditLink {
                                onsave: onsave,
                                link: link,
                            } },
                            ProfileAction::None => rsx! { () },
                        }
                    }
                }
            }
            div {
                class: "flex flex-col gap-4 fixed md:absolute lg:absolute right-4 md:right-0 lg:right-0 bottom-20 md:bottom-0 lg:bottom-0",
                DeleteLinkButton {
                    onclick: move |_| {
                        if *action.get() == ProfileAction::Delete {
                            action.set(ProfileAction::None);
                        } else {
                            action.set(ProfileAction::Delete);
                        }
                    },
                }
                EditLinkButton {
                    onclick: move |_| action.set(ProfileAction::Edit),
                }
                AddLinkButton {
                    onclick: move |_| action.set(ProfileAction::Add),
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

#[derive(Props)]
struct CtaProps<'a> {
    children: Element<'a>,
}

fn Cta<'a>(cx: Scope<'a, CtaProps<'a>>) -> Element {
    cx.render(
        rsx! {
            button {
                class: "dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full",
                &cx.props.children
            }
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

#[derive(Props)]
struct SheetProps<'a> {
    children: Element<'a>,
    onclose: EventHandler<'a>,
}

fn Sheet<'a>(cx: Scope<'a, SheetProps<'a>>) -> Element<'a> {
    let shown = use_state(cx, || true);
    let translate_y = use_state(cx, || "translate-y-full");
    let _ = use_future(cx, (), |_| {
        to_owned![translate_y, shown];
        async move {
            let duration = Duration::from_millis(5);
            sleep(duration).await;
            match *shown.current() {
                true => translate_y.set("translate-y-0"),
                false => translate_y.set("translate-y-full"),
            };
        }
    });
    return cx.render(
        rsx! {
            div {
                class: "transition ease-out overflow-y-auto h-fit {translate_y} left-0 right-0 bottom-0 lg:max-w-3xl lg:mx-auto fixed p-6 rounded-md bg-yellow-400 text-zinc-900 dark:bg-zinc-800 dark:text-yellow-400 z-10",
                ontransitionend: move |_| {
                    to_owned![translate_y];
                    if *translate_y == "translate-y-full" {
                        cx.props.onclose.call(())
                    }
                },
                &cx.props.children,
                div {
                    class: "absolute right-4 top-4",
                    CircleButtonSmall {
                        onclick: move |_| translate_y.set("translate-y-full"),
                        disabled: false,
                        Icon {
                            width: 24,
                            height: 24,
                            icon: BsX
                        }
                    }
                }
            }
        }
    );
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

#[derive(Props)]
struct RoundedRect<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    children: Element<'a>,
}

fn RoundedRect<'a>(cx: Scope<'a, RoundedRect<'a>>) -> Element<'a> {
    cx.render(
        rsx! {
            button {
                class: "dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full",
                onclick: move |event| cx.props.onclick.call(event),
                &cx.props.children
            }
        }
    )
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
fn CircleButtonSmall<'a>(
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
            class: "rounded-full bg-zinc-500 text-black w-6 h-6 disabled:opacity-50 flex justify-center items-center",
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
fn EditLinkButton<'a>(
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
                    Icon { width: 40, height: 40, icon: BsPencil }
                }
            }
            div { "Edit" }
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
                    Icon { width: 40, height: 40, icon: BsDash }
                }
            }
            div { "Delete" }
        }
    })
}

#[derive(Props)]
struct MultilineTextInput<'a> {
    #[props(optional)]
    placeholder: Option<&'a str>,
    #[props(optional)]
    autofocus: Option<bool>,
    value: String,
    #[props(optional)]
    onenter: Option<EventHandler<'a, KeyboardEvent>>,
    #[props(optional)]
    oninput: Option<EventHandler<'a, FormEvent>>,
}

fn MultilineTextInput<'a>(cx: Scope<'a, MultilineTextInput<'a>>) -> Element {
    let placeholder = match cx.props.placeholder {
        Some(p) => p,
        None => "",
    };
    let autofocus = match cx.props.autofocus {
        Some(af) => af,
        None => false,
    };
    let value = &cx.props.value;
    let oninput = move |event: FormEvent| {
        if let Some(oninput) = &cx.props.oninput {
            oninput.call(event);
        }
    };
    let onkeypress = move |event: KeyboardEvent| {
        match event.key() {
            Key::Enter => {
                if let Some(onenter) = &cx.props.onenter {
                    onenter.call(event);
                }
            }
            _ => (),
        };
    };
    cx.render(rsx! {
        textarea {
            placeholder: placeholder,
            class: "bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full",
            value: "{value}",
            rows: 3,
            autofocus: autofocus,
            oninput: oninput,
            onkeypress: onkeypress,
        }
    })
}

#[derive(Props)]
struct TextInputProps<'a> {
    #[props(optional)]
    name: Option<&'a str>,
    #[props(optional)]
    value: Option<&'a str>,
    #[props(optional)]
    oninput: Option<EventHandler<'a, FormEvent>>,
}

fn TextInput<'a>(cx: Scope<'a, TextInputProps<'a>>) -> Element {
    let value = match &cx.props.value {
        Some(v) => v,
        None => "",
    };
    cx.render(
        rsx! {
            input {
                r#type: "text",
                name: "{cx.props.name:?}",
                value: value,
                class: "bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full",
                oninput: move |event| {
                    if let Some(oninput) = &cx.props.oninput {
                        oninput.call(event);
                    }
                }
            }
        }
    )
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
    onenter: Option<EventHandler<'a, Event<FormData>>>,
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
                onsubmit: |event| {
                    if let Some(oe) = onenter.as_ref() {
                        oe.call(event);
                    }
                },
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
    use_init_atom_root(cx);
    let AppProps {
        current_user,
        links,
        ..
    } = cx.props;
    let set_user = use_set(cx, USER);
    set_user(current_user.clone());
    return cx.render(rsx! {
        Profile {
            user: current_user,
            links: links.to_owned()
        }
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
    let bio = match bio {
        Some(b) => b,
        None => String::with_capacity(0),
    };
    res.render(Text::Html(render_lazy(rsx! (
        Layout {
            csrf_token: props.csrf_token,
            current_user: props.current_user,
            div {
                class: "flex flex-col max-w-3xl px-4 lg:px-0 mx-auto gap-8 text-center items-center h-full relative w-full",
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
                    "{bio}"
                }
                LinkList {
                    links: links
                }
                div {
                    class: "flex flex-col gap-4 fixed right-4 bottom-20",
                    a {
                        href: "/profile",
                        "Edit"
                    }
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
    let csrf_token = depot
        .csrf_token()
        .map(|s| &**s)
        .unwrap_or_default()
        .to_string();

    if let Some(current_user) = maybe_user {
        let links = Link::all_by_user_id(current_user.id).await;
        WebSocketUpgrade::new()
            .upgrade(req, res, |ws| async move {
                _ = view
                    .launch_with_props::<AppProps>(
                        dioxus_liveview::salvo_socket(ws),
                        app,
                        AppProps {
                            csrf_token,
                            current_user,
                            links,
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
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let database_url = env::var("DATABASE_URL")?;
    database::init(database_url).await;
    database::migrate().await?;
    let addr: SocketAddr = ([127, 0, 0, 1], 9001).into();
    let router = routes();

    println!("Listening on {}", addr);

    Server::new(TcpListener::bind(addr)).serve(router).await;

    return Ok(());
}
