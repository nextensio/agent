//
// NXT Protected Router
//
const express = require('express');
const path = require('path');

const router = express.Router();

router.use('/about', (req, res) => {
  console.log('NXT GW about route, req.uc', req.userContext);
  console.log('NXT GW about route, res', res.headers);

  // Go to the nxt controller to get session id

  if (req.userContext) {
      // console.log("REQ Header: x-nxt-token value", req.headers['x-nxt-token']);
      console.log("NXT Gateway sent about.html from " + __dirname);
      res.sendFile(path.join(__dirname + '/about.html'));
  } 
  else {
      console.log("NXT GW, /about not login yet");
      res.end();
  }
});

router.use('/logout', (req, res) => {
  console.log('NXT GW logout route');

  if (req.userContext) {
      const idToken = req.userContext.tokens.id_token;
      const to = encodeURI(process.env.HOST_URL); // point back to localhost:8081 (agent listener)
      const params = `id_token_hint=${idToken}&post_logout_redirect_uri=${to}`;
      req.logout();
      res.redirect(`${process.env.OKTA_ORG_URL}/oauth2/default/v1/logout?${params}`);
  } else {
      res.redirect('/');
  }
});

// router.use('/', (req, res) => {
//   console.log('NXT GW/AUTH default route, statusCode: ', res.statusCode);
//   if (req.userContext) {
//     //console.log(req.userContext);
//     const idToken = req.userContext.tokens.id_token;
//     res.setHeader("x-nxt-token", `${idToken}`);
//     res.send(`Hello ${req.userContext.userinfo.name}!
//       <form method="POST" action="/logout">
//         <button type="submit">Logout</button>
//       </form>
//     `);
//   } 
//   else {
//     res.send('Please <a href="/login">login</a>');
//   }
//   //res.json({ title: 'Registration Successful!', todo, userinfo: req.userContext.userinfo });
// });

module.exports = router
