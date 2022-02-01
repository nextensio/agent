use fltk::{prelude::*, *};

#[derive(Debug, Clone)]
pub enum Message {
    LoginStatus(String),
    Login,
}

pub fn gui_main(client_id: String) {
    let a = app::App::default().with_scheme(app::Scheme::Gtk);
    let mut win = window::Window::default().with_size(400, 100);
    let mut col = group::Flex::default_fill().column();
    let (s, r) = app::channel::<Message>();
    let sc = s.clone();
    std::thread::spawn(|| super::pkce::web_server(client_id, sc));
    let mut login = main_panel(&mut col, s);
    col.end();
    win.resizable(&col);
    win.set_color(enums::Color::from_rgb(250, 250, 250));
    win.end();
    win.show();
    win.size_range(400, 100, 0, 0);
    while a.wait() {
        if let Some(msg) = r.recv() {
            match msg {
                Message::Login => {
                    let err = open::that("http://localhost:8180/login");
                    println!("{:?}", err);
                }
                Message::LoginStatus(status) => {
                    login.set_label(&status);
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
    let w = frame::Frame::default().with_label("");

    let l: Box<button::Button>;
    let mut brow = group::Flex::default().row();
    {
        frame::Frame::default();
        let mut login = create_button("Login");
        login.emit(sender, Message::Login);

        brow.set_size(&login, 250);
        brow.end();
        l = Box::new(login);
    }

    let b = frame::Frame::default();

    frame::Frame::default();

    parent.set_size(&w, 60);
    parent.set_size(&brow, 30);
    parent.set_size(&b, 30);

    l
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

    parent.set_size(&spacer, 0);
    parent.set_size(&bp, 100);

    b
}

fn main_panel(parent: &mut group::Flex, sender: fltk::app::Sender<Message>) -> Box<button::Button> {
    frame::Frame::default();

    let mut mp = group::Flex::default().row();
    let b = middle_panel(&mut mp, sender);
    mp.end();

    frame::Frame::default();

    parent.set_size(&mp, 200);

    b
}

fn create_button(caption: &str) -> button::Button {
    let mut btn = button::Button::default().with_label(caption);
    btn.set_color(enums::Color::from_rgb(225, 225, 225));
    btn
}
