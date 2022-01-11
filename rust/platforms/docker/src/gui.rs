use fltk::{prelude::*, *};

#[derive(Debug, Clone)]
pub enum Message {
    Username(String),
    Password(String),
    Login,
}

pub fn gui_main() {
    let a = app::App::default().with_scheme(app::Scheme::Gtk);
    let mut win = window::Window::default().with_size(400, 200);
    let mut col = group::Flex::default_fill().column();
    let (s, r) = app::channel::<Message>();
    let mut username = "".to_string();
    let mut password = "".to_string();
    let mut login = main_panel(&mut col, s.clone());
    col.end();
    win.resizable(&col);
    win.set_color(enums::Color::from_rgb(250, 250, 250));
    win.end();
    win.show();
    win.size_range(400, 200, 0, 0);
    let mut onboarded = false;
    while a.wait() {
        if let Some(msg) = r.recv() {
            match msg {
                Message::Username(u) => username = u,
                Message::Password(p) => password = p,
                Message::Login => {
                    if !onboarded {
                        let token = super::pkce::authenticate(false, &username, &password);
                        if let Some(t) = token {
                            std::thread::spawn(move || {
                                super::do_onboard(false, "server.nextensio.net:8080".to_string(), t)
                            });
                            onboarded = true;
                            login.set_label("Login Succesful");
                        } else {
                            login.set_label("Login failed");
                        }
                    }
                }
            }
        }
    }
}

fn buttons_panel(
    parent: &mut group::Flex,
    sender: fltk::app::Sender<Message>,
) -> Box<button::Button> {
    frame::Frame::default();
    let w = frame::Frame::default().with_label("Nextensio Login");

    let mut urow = group::Flex::default().row();
    {
        frame::Frame::default()
            .with_label("Username:")
            .with_align(enums::Align::Inside | enums::Align::Right);
        let mut username = input::Input::default();
        let s = sender.clone();
        username.set_callback(move |u| s.send(Message::Username(u.value())));
        urow.set_size(&username, 180);
        urow.end();
    }

    let mut prow = group::Flex::default().row();
    {
        frame::Frame::default()
            .with_label("Password:")
            .with_align(enums::Align::Inside | enums::Align::Right);
        let mut password = input::SecretInput::default();
        let s = sender.clone();
        password.set_callback(move |p| s.send(Message::Password(p.value())));

        prow.set_size(&password, 180);
        prow.end();
    }

    let pad = frame::Frame::default();
    let l: Box<button::Button>;
    let mut brow = group::Flex::default().row();
    {
        frame::Frame::default();
        let mut login = create_button("Login");
        login.emit(sender.clone(), Message::Login);

        brow.set_size(&login, 160);
        brow.end();
        l = Box::new(login);
    }

    let b = frame::Frame::default();

    frame::Frame::default();

    parent.set_size(&w, 60);
    parent.set_size(&urow, 30);
    parent.set_size(&prow, 30);
    parent.set_size(&pad, 1);
    parent.set_size(&brow, 30);
    parent.set_size(&b, 30);

    return l;
}

fn middle_panel(
    parent: &mut group::Flex,
    sender: fltk::app::Sender<Message>,
) -> Box<button::Button> {
    frame::Frame::default();

    let spacer = frame::Frame::default();

    let mut bp = group::Flex::default().column();
    let b = buttons_panel(&mut bp, sender);
    bp.end();

    frame::Frame::default();

    parent.set_size(&spacer, 10);
    parent.set_size(&bp, 300);

    return b;
}

fn main_panel(parent: &mut group::Flex, sender: fltk::app::Sender<Message>) -> Box<button::Button> {
    frame::Frame::default();

    let mut mp = group::Flex::default().row();
    let b = middle_panel(&mut mp, sender);
    mp.end();

    frame::Frame::default();

    parent.set_size(&mp, 200);

    return b;
}

fn create_button(caption: &str) -> button::Button {
    let mut btn = button::Button::default().with_label(caption);
    btn.set_color(enums::Color::from_rgb(225, 225, 225));
    btn
}
