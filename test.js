const fetch = require("node-fetch");
var fs = require("fs");

const requests = require("./requests");

const fetchByPid = pid => {
  var dir = "./download/" + pid.toString();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
  requests.fetchBehavior(pid);
  requests.fetchPcap(pid);
  requests.fetchSummary(pid);
};

fetchByPid(17784);
// res
//   .then(ret => ret.text())
//   .then(ret => {
//     fs.writeFile("test.html", ret, function(err) {
//       if (err) {
//         return console.log(err);
//       }
//       console.log("The file was saved!");
//     });
//   });
