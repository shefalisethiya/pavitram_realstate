const express = require("express");
const path = require("path");

const app = express();
const port = 8085;

// Set the static folder to serve HTML, CSS, JS, etc.
app.use(express.static(path.join(__dirname, "public")));

// Example for hitting another endpoint from the default endpoint
app.get("/", (req, res) => {
  // Redirect to another endpoint
  res.redirect("/dropdown");

  // Or render another endpoint's view
  // res.render('another-endpoint');
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Server running at http://0.0.0.0:${port}/`);
});
