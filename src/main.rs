#![allow(non_snake_case)]

mod database;
mod events;

use anyhow::Result;
use dioxus::prelude::*;
use dioxus_free_icons::icons::bs_icons::*;
use dioxus_free_icons::Icon;
use dioxus_liveview::LiveViewPool;
use dioxus_ssr::render_lazy;
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
use std::convert::TryInto;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, Level};

use crate::database::{db, Link, User};
use crate::events::*;

pub const HOME: &str = "/";
pub const LOGIN: &str = "/login";
pub const LOGOUT: &str = "/logout";
pub const EDIT_PROFILE: &str = "/profile";
pub const PROFILE: &str = "/@<username>";

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
        if let Ok(user) = db().user_by_id(id).await {
            depot.inject(user);
        }
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
                        .push(at(PROFILE).get(profile))
                        .push(at(LOGOUT).post(logout)),
                )
                .push(
                    Router::new()
                        .hoop(auth)
                        .hoop(affix::inject(arc_view))
                        .push(at(EDIT_PROFILE).get(edit_profile))
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

#[derive(Props)]
struct BodyProps<'a> {
    children: Element<'a>,
    csrf_token: &'a str,
    #[props(!optional)]
    current_user: Option<&'a User>,
    #[props(optional)]
    liveview_js: Option<String>,
}

impl<'a> BodyProps<'a> {
    pub async fn from_depot(depot: &mut Depot) -> BodyProps {
        let ws_addr = env::var("WS_ADDR").unwrap();
        let current_user = depot.obtain::<User>();
        let liveview_js = Some(dioxus_liveview::interpreter_glue(&ws_addr));
        let csrf_token = depot.csrf_token().map(|s| &**s).unwrap_or_default();

        return BodyProps {
            csrf_token,
            current_user,
            liveview_js,
            children: Element::default(),
        };
    }
}

fn Body<'a>(cx: Scope<'a, BodyProps<'a>>) -> Element {
    let BodyProps {
        children,
        csrf_token,
        current_user,
        liveview_js,
    } = cx.props;
    use_shared_state_provider(cx, || AppState {
        csrf_token: csrf_token.to_string(),
        current_user: current_user.cloned(),
    });
    let liveview_js = match liveview_js {
        Some(js) => js.clone(),
        None => String::with_capacity(0),
    };
    cx.render(rsx! {
        div {
            children
            "{liveview_js}"
        }
    })
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

fn Layout<'a>(cx: Scope<'a, ChildrenProps<'a>>) -> Element<'a> {
    cx.render(rsx! {
        "<!DOCTYPE html>"
        "<html lang=en>"
            head {
                title {
                  "all your links"
                }
                meta { charset: "utf-8" }
                meta { name: "viewport", content:"width=device-width" }
                link { rel: "stylesheet", href: "/output.css" }
            }
            body {
                class: "dark:bg-zinc-900 dark:text-yellow-400 bg-yellow-400 text-zinc-900 font-sans max-w-3xl mx-auto mb-[150px]",
                &cx.props.children
            }
        "</html>"
    })
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

#[derive(Props, PartialEq)]
struct HomeProps {
    error: Option<CreateUserError>,
}

fn Home<'a>(cx: Scope<'a, HomeProps>) -> Element {
    let HomeProps { error } = cx.props;
    let err = match error {
        Some(err) => err.to_string(),
        None => String::default(),
    };
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-16 px-4 md:px-0 mt-16 md:mt-0",
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
                        TextInput {
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
    let BodyProps {
        csrf_token,
        current_user,
        ..
    } = BodyProps::from_depot(depot).await;
    Text::Html(render_lazy(rsx! {
        Layout {
            Body {
                csrf_token: csrf_token,
                current_user: current_user,
                Nav {}
                Home {}
            }
        }
    }))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
}

#[handler]
async fn signup(req: &mut Request, depot: &mut Depot, res: &mut Response) -> Result<()> {
    let new_user: NewUser = req.parse_form().await?;
    let user: User = db().insert_user(new_user.username).await?;
    let default_links: Vec<(&str, &str)> = vec![
        ("twitch.tv/", "twitch"),
        ("twitter.com/", "twitter"),
        ("instagram.com/", "instagram"),
        ("youtube.com/", "youtube"),
        ("tiktok.com/", "tiktok"),
        ("discord.com/", "discord"),
        ("github.com/", "github"),
        ("stackoverflow.com/", "stackoverflow"),
    ];
    for (url, name) in default_links {
        let url = format!("{}{}", url, user.username);
        let _ = db().insert_link(user.id, url, Some(name.to_string())).await;
    }
    let session = depot.session_mut().unwrap();
    _ = session.insert("user_id", user.id)?;
    res.render(Redirect::other(format!("/@{}", user.username)));
    return Ok(());
}

#[derive(Props)]
struct LoginProps<'a> {
    message: &'a str,
}

fn Login<'a>(cx: Scope<'a, LoginProps<'a>>) -> Element<'a> {
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-16",
            Header {}
            Form {
                action: "/login",
                div {
                    class: "flex flex-col gap-2 md:max-w-lg md:mx-auto",
                    div {
                        class: "flex flex-col",
                        div {
                            class: "dark:text-white text-black",
                            "{cx.props.message}"
                        }
                        TextInput {
                            name: "login_code",
                            autofocus: true
                        }
                    }
                    Cta {
                        "login"
                    }
                }
            }
        }
    })
}

#[handler]
async fn get_login(depot: &mut Depot) -> Text<String> {
    let BodyProps {
        csrf_token,
        current_user,
        ..
    } = BodyProps::from_depot(depot).await;
    Text::Html(render_lazy(rsx! {
        Layout {
            Nav {}
            Body {
                csrf_token: csrf_token,
                current_user: current_user,
                Login {
                    message: ""
                }
            }
        }
    }))
}

impl Link {
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
}

#[derive(Props)]
struct LinkIconComponentProps<'a> {
    link: &'a Link,
}

fn LinkIconComponent<'a>(cx: Scope<'a, LinkIconComponentProps<'a>>) -> Element<'a> {
    cx.render(match &cx.props.link.icon() {
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
struct EditBioProps<'a> {
    bio: String,
    onsave: EventHandler<'a, String>,
}

fn EditBio<'a>(cx: Scope<'a, EditBioProps<'a>>) -> Element<'a> {
    let EditBioProps { onsave, bio } = cx.props;
    let onsubmit = move |event: FormEvent| {
        if let Some(bio) = event.values.get("bio") {
            onsave.call(bio.clone());
        }
    };
    cx.render(rsx! {
        div {
            class: "pt-8",
            form {
                class: "flex flex-col gap-4",
                onsubmit: onsubmit,
                MultilineTextInput {
                    value: "{bio}",
                    name: "bio",
                    placeholder: "Add your bio here"
                }
                SheetSubmit {
                    value: "Save bio"
                }
            }
        }
    })
}

#[derive(Props)]
struct DeleteLinkProps<'a> {
    num_links: usize,
    ondelete: EventHandler<'a>,
}

fn DeleteLink<'a>(cx: Scope<'a, DeleteLinkProps<'a>>) -> Element {
    let DeleteLinkProps {
        ondelete,
        num_links,
    } = cx.props;
    let s = match num_links {
        1 => "link",
        _ => "links",
    };
    cx.render(rsx! {
        div {
            class: "flex gap-12 pt-8",
            RoundedRect {
                onclick: move |_| ondelete.call(()),
                "Delete ({num_links}) {s}?"
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
    #[props(optional)]
    onselect: Option<EventHandler<'a, i64>>,
    show_select: bool,
}

fn ShowLink<'a>(cx: Scope<'a, ShowLinkProps<'a>>) -> Element {
    let ShowLinkProps {
        link,
        onselect,
        show_select,
    } = cx.props;
    let display = match &link.name {
        Some(name) => name,
        None => &link.url,
    };
    let onclick = move |_| {
        if let Some(onselect) = onselect {
            onselect.call(link.id)
        }
    };
    cx.render(rsx! {
        div {
            class: "flex gap-4 border-t dark:border-zinc-700 border-zinc-300 p-4 pt-4 w-full items-center",
            if *show_select {
                rsx! {
                    SelectButton {
                        onclick: onclick
                    }
                }
            }
            LinkIconComponent {
                link: link
            }
            a {
                class: "grow text-left",
                "{display}"
            }
        }
    })
}

#[derive(Props)]
struct LinkListProps<'a> {
    links: Vec<Link>,
    #[props(optional)]
    onselect: Option<EventHandler<'a, i64>>,
    show_select: bool,
}

fn LinkList<'a>(cx: Scope<'a, LinkListProps<'a>>) -> Element<'a> {
    let LinkListProps {
        links,
        onselect,
        show_select,
    } = cx.props;
    let onselect = move |id| {
        if let Some(onselect) = onselect {
            onselect.call(id)
        }
    };
    cx.render(rsx! {
        div {
            links.iter().map(|link| {
                rsx! {
                    ShowLink {
                        key: "{link.id}",
                        link: link,
                        onselect: onselect,
                        show_select: *show_select
                    }
                }
            })
        }
    })
}

#[derive(Props)]
struct BioProps<'a> {
    bio: String,
    onselect: EventHandler<'a>,
}

fn Bio<'a>(cx: Scope<'a, BioProps<'a>>) -> Element {
    let BioProps { bio, onselect } = &cx.props;
    let bio = if bio.is_empty() {
        String::from("<Add your bio here>")
    } else {
        bio.to_owned()
    };
    cx.render(rsx! {
        div {
            class: "flex gap-4",
            SelectButton {
                onclick: move |_| onselect.call(())
            }
            div {
                "{bio}"
            }
        }
    })
}

#[derive(Props)]
struct AddEditLinkProps<'a> {
    onsave: EventHandler<'a, (Option<i64>, String, Option<String>)>,
    #[props(!optional)]
    link: Option<Link>,
    username: &'a String,
}

fn AddEditLink<'a>(cx: Scope<'a, AddEditLinkProps<'a>>) -> Element {
    let AddEditLinkProps {
        onsave,
        link,
        username,
    } = &cx.props;
    let (id, url, name) = match link {
        Some(link) => (Some(link.id), link.url.clone(), link.name.clone()),
        None => (None, String::default(), None),
    };
    let url = use_state(cx, || url);
    let on_icon_click = move |icon| {
        to_owned![url];
        let u = Link::url_from_icon(icon);
        let new_url = format!("{}{}", u, username);
        url.set(new_url);
    };
    let onsubmit = move |event: FormEvent| {
        let values = &event.values;
        let url = values
            .get("url")
            .cloned()
            .unwrap_or(String::with_capacity(0));
        let name = values.get("name").cloned();
        onsave.call((id, url, name));
    };
    let name = name.unwrap_or(String::default());
    cx.render(rsx! {
        div {
            class: "flex flex-col gap-8",
            div {
                class: "flex flex-col gap-2",
                div { class: "font-bold", "select a link" }
                IconList {
                    onclick: on_icon_click
                }
            }
            form {
                onsubmit: onsubmit,
                class: "flex flex-col gap-8",
                div {
                    class: "flex flex-col gap-2",
                    label { r#for: "url", class: "font-bold", "change the url" }
                    TextInput {
                        value: "{url}",
                        name: "url"
                    }
                }
                div {
                    class: "flex flex-col gap-2",
                    label { r#for: "name", class: "font-bold", "add a name instead of url" }
                    TextInput {
                        name: "name",
                        value: "{name}",
                    }
                }
                input {
                    r#type: "submit",
                    class: "dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full",
                    value: "Save link"
                }
            }
        }
    })
}

fn EditProfile<'a>(cx: Scope<'a, ProfileProps<'a>>) -> Element<'a> {
    let ProfileProps { user, links } = cx.props;
    let links = use_state(cx, || links.clone());
    let action = use_state(cx, || ProfileAction::None);
    let link_ids: &UseState<Vec<i64>> = use_state(cx, || Vec::new());
    let User {
        id: user_id,
        photo,
        username,
        bio,
        ..
    } = user;
    let bio_state = use_state(cx, || bio.clone());
    let bio_selected = use_state(cx, || false);
    let bio = match bio_state.get() {
        Some(b) => b.clone(),
        None => String::default(),
    };
    let onsave = move |(id, url, name): (Option<i64>, String, Option<String>)| {
        to_owned![user_id, links, action];
        if url.is_empty() {
            todo!("Show an error or something that url needs to be filled in");
            // action.set(ProfileAction::None);
        } else {
            cx.spawn(async move {
                if let Some(id) = id {
                    let _ = db().update_link(id, url, name).await;
                } else {
                    let _ = db().insert_link(user_id, url, name).await;
                }
                let new_links = db().links_by_user_id(user_id).await;
                links.set(new_links);
                action.set(ProfileAction::None);
            });
        }
    };
    let onselect = move |id: i64| {
        to_owned![link_ids];
        let mut ids = link_ids.get().clone();
        if let Some(idx) = ids.iter().position(|x| *x == id) {
            ids.remove(idx);
        } else {
            ids.push(id);
        }
        link_ids.set(ids);
    };
    let ondelete = move |_| {
        to_owned![links, user_id, action, link_ids];
        let ids: Vec<i64> = link_ids.get().clone().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        cx.spawn(async move {
            let _ = db().delete_links(ids).await;
            let new_links = db().links_by_user_id(user_id).await;
            link_ids.set(vec![]);
            links.set(new_links);
            action.set(ProfileAction::None);
        });
    };
    let link_id = link_ids.get().iter().last();
    let link = if let Some(id) = link_id {
        links.iter().find(|l| l.id == *id)
    } else {
        None
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
            Bio {
                bio: bio,
                onselect: move |_| on_select_bio(bio_selected)
            }
            LinkList {
                links: links.to_vec(),
                onselect: onselect,
                show_select: true
            }
            if **action != ProfileAction::None {
                rsx! {
                    Sheet {
                        onclose: move |_| action.set(ProfileAction::None),
                        match **action {
                            ProfileAction::Add => rsx! { AddEditLink {
                                username: username,
                                onsave: onsave,
                                link: None
                            } },
                            ProfileAction::Delete => rsx! { DeleteLink {
                                num_links: link_ids.len(),
                                ondelete: ondelete
                            } },
                            ProfileAction::Edit => rsx! { AddEditLink {
                                username: username,
                                onsave: onsave,
                                link: link.cloned(),
                            } },
                            ProfileAction::EditBio => rsx! { EditBio {
                                bio: bio_state.get().as_ref().cloned().unwrap_or_default(),
                                onsave: move |bio| on_save_bio(cx, bio, user_id, bio_state, action),
                            } },
                            ProfileAction::None => rsx! { () },
                        }
                    }
                }
            }
            div {
                class: "flex flex-col gap-4 fixed md:absolute lg:absolute right-4 md:right-0 lg:right-0 bottom-20 md:bottom-0 lg:bottom-0",
                DeleteLinkButton {
                    disabled: **bio_selected,
                    onclick: move |_| {
                        if *action.get() == ProfileAction::Delete {
                            action.set(ProfileAction::None);
                        } else {
                            action.set(ProfileAction::Delete);
                        }
                    },
                }
                EditLinkButton {
                    onclick: move |_| {
                        if *bio_selected.get() {
                            action.set(ProfileAction::EditBio);
                        } else if *action.get() == ProfileAction::Edit {
                            action.set(ProfileAction::None);
                        } else {
                            action.set(ProfileAction::Edit);
                        }
                    },
                }
                AddLinkButton {
                    disabled: **bio_selected,
                    onclick: move |_| {
                        if *action.get() == ProfileAction::Add {
                            action.set(ProfileAction::None);
                        } else {
                            action.set(ProfileAction::Add);
                        }
                    },
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
    let maybe_user: Option<User> = db().user_by_login_code(login_user.login_code).await.ok();
    let session = depot.session_mut().unwrap();
    if let Some(u) = maybe_user {
        let _ = session.insert("user_id", u.id)?;
        let url = format!("/@{}", u.username);
        res.render(Redirect::other(url));
    } else {
        // TODO exponential backoff
        let BodyProps {
            csrf_token,
            current_user,
            ..
        } = BodyProps::from_depot(depot).await;
        res.render(Text::Html(render_lazy(rsx! {
            Layout {
                Body {
                    csrf_token: csrf_token,
                    current_user: current_user,
                    Nav {}
                    Login {
                        message: "Invalid login code"
                    }
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
struct TextInputProps<'a> {
    #[props(optional)]
    name: Option<&'a str>,
    #[props(optional)]
    autofocus: Option<bool>,
    #[props(optional)]
    placeholder: Option<&'a str>,
    #[props(optional)]
    value: Option<&'a str>,
}

#[derive(Props)]
struct ChildrenProps<'a> {
    children: Element<'a>,
}

fn Cta<'a>(cx: Scope<'a, ChildrenProps<'a>>) -> Element {
    cx.render(
        rsx! {
            button {
                class: "dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full",
                &cx.props.children
            }
        }
    )
}

fn Submit<'a>(cx: Scope<'a, TextInputProps<'a>>) -> Element<'a> {
    let value = match &cx.props.value {
        Some(v) => v,
        None => "",
    };
    cx.render(rsx! {
        input {
            r#type: "submit",
            value: "{value}",
            class: "cursor-pointer"
        }
    })
}

fn SheetSubmit<'a>(cx: Scope<'a, TextInputProps<'a>>) -> Element {
    let TextInputProps { value, .. } = &cx.props;
    let value = value.unwrap_or_default();
    cx.render(rsx! {
        input {
            r#type: "submit",
            value: "{value}",
            class: "dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 rounded-md px-6 py-3 drop-shadow uppercase font-bold text-xl w-full cursor-pointer",
        }
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
            class: "grid grid-cols-4 gap-8 md:mx-auto place-items-center",
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

const NAV_ICON_SIZE: u32 = 24;

#[derive(Props, PartialEq)]
struct NavLinksProps {
    #[props(!optional)]
    current_user: Option<User>,
    profile_href: String,
}

fn NavLinks<'a>(cx: Scope<'a, NavLinksProps>) -> Element<'a> {
    let NavLinksProps {
        current_user,
        profile_href,
    } = cx.props;
    cx.render(rsx! {
        nav {
            class: "gap-8 justify-center py-8 hidden md:flex",
            a {
                href: HOME,
                span { "Home" }
            }
            {
                match *current_user {
                    Some(_) => {
                        rsx! {
                            div {
                                class: "flex gap-8",
                                a {
                                    href: "{profile_href}",
                                    span { "Profile" }
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
                            span { "Login" }
                        }
                    }
                }
            }
        }
    })
}

#[derive(Props, PartialEq)]
struct NavBarProps {
    profile_href: String,
}

fn NavBar<'a>(cx: Scope<'a, NavBarProps>) -> Element<'a> {
    let NavBarProps { profile_href } = cx.props;
    cx.render(rsx! {
        nav {
            class: "flex md:hidden lg:hidden justify-between items-center fixed bottom-0 left-0 right-0 z-10",
            NavButton {
                a {
                    href: HOME,
                    class: "flex flex-col justify-center items-center",
                    Icon {
                        width: NAV_ICON_SIZE,
                        height: NAV_ICON_SIZE,
                        icon: BsHouseFill
                    }
                    div {
                        "Home" 
                    }
                }
            }
            NavButton {
                a {
                    href: "{profile_href}",
                    class: "flex flex-col justify-center items-center",
                    Icon {
                        width: NAV_ICON_SIZE,
                        height: NAV_ICON_SIZE,
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
                            width: NAV_ICON_SIZE,
                            height: NAV_ICON_SIZE,
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

fn Nav<'a>(cx: Scope<'a>) -> Element<'a> {
    let app_state = use_shared_state::<AppState>(cx);
    let current_user = match &app_state {
        Some(app_state) => app_state.read().current_user.clone(),
        None => None,
    };
    let profile_href = match &current_user {
        Some(u) => format!("/@{}", u.username),
        None => String::with_capacity(0),
    };
    cx.render(rsx! {
        NavLinks {
            current_user: current_user,
            profile_href: profile_href.clone()
        }
        NavBar {
            profile_href: profile_href.clone()
        }
    })
}

fn NavButton<'a>(cx: Scope<'a, ChildrenProps<'a>>) -> Element<'a> {
    cx.render(rsx!(div {
        class: "bg-zinc-700 text-yellow-400 py-4 flex flex-auto text-center justify-center",
        &cx.props.children
    }))
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

#[derive(Props)]
struct CircleButtonProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
    children: Element<'a>,
}

fn CircleButton<'a>(cx: Scope<'a, CircleButtonProps<'a>>) -> Element<'a> {
    let CircleButtonProps {
        disabled, onclick, ..
    } = cx.props;
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

#[derive(Props)]
struct CircleLink<'a> {
    href: &'a str,
    children: Element<'a>,
}

fn CircleLink<'a>(cx: Scope<'a, CircleLink<'a>>) -> Element<'a> {
    let CircleLink { children, href } = cx.props;
    cx.render(rsx! {
        a {
            class: "rounded-full dark:bg-yellow-400 dark:text-zinc-900 bg-zinc-900 text-yellow-400 p-3 w-12 h-12 disabled:opacity-50",
            href: *href,
            children
        }
    })
}

#[derive(Props)]
struct CircleButtonSmallProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
    children: Element<'a>,
}

fn CircleButtonSmall<'a>(cx: Scope<'a, CircleButtonSmallProps<'a>>) -> Element<'a> {
    let CircleButtonSmallProps {
        onclick, disabled, ..
    } = cx.props;
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

#[derive(Props)]
struct AddLinkButtonProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
}

fn AddLinkButton<'a>(cx: Scope<'a, AddLinkButtonProps<'a>>) -> Element<'a> {
    let AddLinkButtonProps { onclick, disabled } = cx.props;
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

#[derive(Props)]
struct EditLinkButtonProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
}

fn EditLinkButton<'a>(cx: Scope<'a, EditLinkButtonProps<'a>>) -> Element<'a> {
    let EditLinkButtonProps { onclick, disabled } = cx.props;
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

#[derive(Props)]
struct DeleteLinkButtonProps<'a> {
    onclick: EventHandler<'a, MouseEvent>,
    disabled: Option<bool>,
}

fn DeleteLinkButton<'a>(cx: Scope<'a, DeleteLinkButtonProps<'a>>) -> Element<'a> {
    let DeleteLinkButtonProps { onclick, disabled } = cx.props;
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

fn MultilineTextInput<'a>(cx: Scope<'a, TextInputProps<'a>>) -> Element {
    let TextInputProps {
        placeholder,
        autofocus,
        value,
        name,
        ..
    } = cx.props;
    let placeholder = placeholder.unwrap_or("");
    let autofocus = autofocus.unwrap_or(false);
    let value = value.unwrap_or("");
    let name = name.unwrap_or("");
    cx.render(rsx! {
        textarea {
            placeholder: placeholder,
            name: name,
            class: "bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full",
            value: "{value}",
            rows: 3,
            autofocus: autofocus,
        }
    })
}

fn TextInput<'a>(cx: Scope<'a, TextInputProps<'a>>) -> Element {
    let TextInputProps {
        name,
        value,
        autofocus,
        ..
    } = cx.props;
    let autofocus = autofocus.unwrap_or(false);
    let value = value.unwrap_or("");
    let name = name.unwrap_or("");
    cx.render(rsx! {
        input {
            r#type: "text",
            name: name,
            value: value,
            autofocus: autofocus,
            class: "bg-yellow-100 text-black dark:bg-zinc-700 dark:text-white outline-none p-3 text-xl rounded-md w-full",
        }
    })
}

fn app(cx: Scope<AppProps>) -> Element {
    let AppProps {
        current_user,
        links,
        csrf_token,
    } = cx.props;
    return cx.render(rsx! {
        Nav {}
        Body {
            csrf_token: csrf_token,
            current_user: Some(current_user),
            EditProfile {
                user: current_user,
                links: links.to_owned()
            }
        }
    });
}

#[derive(Deserialize)]
struct ProfileParams {
    username: String,
}

#[handler]
async fn profile(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Result<(), StatusError> {
    let params: ProfileParams = req.parse_params().unwrap();
    let user_result = db().user_by_username(params.username).await;
    let user = match user_result {
        Ok(u) => u,
        Err(_) => return Err(StatusError::not_found()),
    };
    let User {
        photo,
        username,
        bio,
        id,
        login_code,
        ..
    } = user;
    let links = db().links_by_user_id(id).await;
    let props = BodyProps::from_depot(depot).await;
    let bio = match bio {
        Some(b) => b,
        None => String::with_capacity(0),
    };
    let is_current_user = match props.current_user {
        Some(cu) => cu.id == id,
        _ => false,
    };
    res.render(Text::Html(render_lazy(rsx! (
        Layout {
            Body {
                csrf_token: props.csrf_token,
                current_user: props.current_user,
                div {
                    class: "flex flex-col max-w-3xl px-4 lg:px-0 mx-auto gap-8 text-center items-center h-full relative w-full pt-8",
                    if is_current_user {
                        rsx! {
                            div {
                                class: "p-4 rounded-md dark:bg-zinc-950 bg-yellow-500 text-left max-w-xs",
                                p { "This is your login code. It's the only way to log back in and edit your profile so don't forget it!" }
                                div { class: "pt-2 font-bold", "{login_code}" }
                            }
                        }
                    }
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
                        links: links,
                        show_select: false
                    }
                    if is_current_user {
                        rsx! {
                            div {
                                class: "flex flex-col gap-4 fixed right-4 bottom-20",
                                div {
                                    class: "flex flex-col gap-2 items-center",
                                    CircleLink {
                                        href: EDIT_PROFILE,
                                        div {
                                            class: "bg-zinc-900 dark:bg-yellow-400 flex justify-center items-center -mt-1.5",
                                            Icon { width: 32, height: 32, icon: BsPencil }
                                        }
                                    }
                                    div { "Edit" }
                                }
                            }
                        }
                    }
                }
            }
        }
    ))));
    return Ok(());
}

#[handler]
async fn edit_profile(res: &mut Response, depot: &mut Depot) -> Result<(), StatusError> {
    let BodyProps {
        current_user,
        csrf_token,
        liveview_js,
        ..
    } = BodyProps::from_depot(depot).await;
    res.render(Text::Html(render_lazy(rsx! (
        Layout {
            Body {
                csrf_token: csrf_token,
                current_user: current_user,
                liveview_js: liveview_js.unwrap(),
                div { id: "main" }
            }
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
    let addr = env::var("ORIGIN").unwrap();
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
        let links = db().links_by_user_id(current_user.id).await;
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
    let log_level = match env::var("LOG_LEVEL") {
        Ok(lev) => lev,
        Err(_) => String::with_capacity(0),
    };
    if log_level.to_lowercase() == "debug" {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .init();
    }

    let database_url = env::var("DATABASE_URL")?;
    database::init(database_url).await;
    database::migrate().await?;
    let addr_string = env::var("SERVER_ADDR")?;
    let addr: SocketAddr = addr_string.parse().unwrap();
    let router = routes();

    println!("Listening on {}", addr);

    Server::new(TcpListener::bind(addr)).serve(router).await;

    return Ok(());
}
