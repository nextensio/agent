pub const HTML_SUCCESS: &str = r##"
<!DOCTYPE html>
<html>
<head>
</head>
<body>

<style>
#message {
  position: absolute;
  top: 50%;
  left: 30%;
  margin: -100px 0 0 -150px;
  background: green;
}
</style>

<div id="message" class="ui text container">
  <h1>Operation Complete, you can close this tab and return to Nextensio client</h1>
</div>

</body>
</html>"##;

pub fn html_error(err: &str) -> String {
    let html_error_1 = r##"
<!DOCTYPE html>
<html>
<head>
</head>
<body>

<style>
#message {
  position: absolute;
  top: 50%;
  left: 30%;
  margin: -100px 0 0 -150px;
  background: green;
}
</style>

<div id="message" class="ui text container">
  <h1>Operation failed"##;

    let html_error_2 = r##", please close this tab, return to Nextensio client and try again</h1>
</div>

</body>
</html>"##;

    format!("{} ({}) {}", html_error_1, err, html_error_2)
}
