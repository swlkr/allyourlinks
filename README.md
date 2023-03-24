# all your links

This is a very simple, mostly not broken link in bio experiment using rust and dioxus liveview

There may or may not be a [live preview here](https://dawn-wave-7794.fly.dev/) depending on when you read this.

### stack

- tailwindcss
- dioxus liveview
- salvo
- rust
- sqlite

### overview

It starts out a regular old ssr app without js/wasm but quickly escalates into a dioxus liveview app after you login.
The auth is a little weird but you'll be right at home if you've tried mullvad vpn's signup.
Instead of taking an email / password or some oauth thing, the app gives you a 16 digit login code (which isn't shown, so you'll have to check sqlite if you want to login again).
This allows you to signup with your username and get logged in all in the same step, no emails, no passwords, just that sweet, sweet login code.
Yes, if you forget this login code, you will not be able to log in again, which is a downside.

### files

| name | description |
| --- | --- |
| database.rs | houses the sqlx queries |
| main.rs | the routes and the dioxus app all kind of mangled together |

### routes

| method | route        | fn               | rendered | description                                                   |
| --- | --- | --- | --- | --- |
| GET    | /            | home()           | ssr      | the landing page with sign up form                            |
| GET    | /login       | get_login()      | ssr      | the page with the login form                                  |
| POST   | /login       | post_login()     | ssr      | exactly what it sounds like                                   |
| GET    | /@<username> | public_profile() | ssr      | the page with the list of configured linkks                   |
| POST   | /logout      | public_profile() | ssr      | the page with the list of configured linkks                   |
| GET    | /profile     | profile()        | ssr      | this is where the dioxus liveview app gets "mounted" to #main |
| GET    | /ws          | connect()        | liveview | the actual websocket connection to initialize liveview        |

### major components

| name | description |
| --- | --- |
| Profile | the entry point to the dioxus liveview app |
| LinkList | the list of links, either in edit or read only mode, depending on `show_select` |
| Layout | this renders the head, meta tags and liveview_js if there is any |
| Body | this renders the body tag of the app |
| Nav | the nav at the top or bottom if the viewport is mobile |
| Form | a reusable form component that helps you out with the csrf token |

That's pretty much it, happy hacking!
