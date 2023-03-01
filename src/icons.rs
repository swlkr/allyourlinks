use dioxus::prelude::*;
pub use dioxus_free_icons::icons::bs_icons::*;
pub use dioxus_free_icons::Icon;

pub fn Instagram(cx: Scope) -> Element {
    cx.render(rsx! {
        Icon {
            width: 32,
            height: 32,
            icon: BsInstagram,
        }
    })
}

pub fn Twitter(cx: Scope) -> Element {
    cx.render(rsx! {
        Icon {
            width: 32,
            height: 32,
            icon: BsTwitter,
        }
    })
}

pub fn Twitch(cx: Scope) -> Element {
    cx.render(rsx! {
        Icon {
            width: 32,
            height: 32,
            icon: BsTwitch,
        }
    })
}

pub fn Youtube(cx: Scope) -> Element {
    cx.render(rsx! {
        Icon {
            width: 32,
            height: 32,
            icon: BsYoutube
        }
    })
}
