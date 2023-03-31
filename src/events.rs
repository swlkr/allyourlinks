use crate::database::{db, Link, User};
use dioxus::prelude::*;

#[derive(Props, PartialEq)]
pub struct ProfileProps<'a> {
    pub user: &'a User,
    pub links: Vec<Link>,
}

#[derive(PartialEq)]
pub enum ProfileAction {
    Add,
    Delete,
    Edit,
    EditBio,
    None,
}

pub fn on_save_bio(
    cx: &Scoped<ProfileProps>,
    bio: String,
    user_id: &i64,
    bio_state: &UseState<Option<String>>,
    action: &UseState<ProfileAction>,
) -> () {
    to_owned![user_id, bio_state, action];
    cx.spawn(async move {
        match db().update_user_bio(user_id, Some(bio)).await {
            Ok(user) => {
                action.set(ProfileAction::None);
                bio_state.set(user.bio);
            }
            _ => (),
        }
    });
}

pub fn on_select_bio(bio_selected: &UseState<bool>) {
    to_owned![bio_selected];
    bio_selected.set(!*bio_selected);
}
