const fetch = require("node-fetch");
var fs = require("fs");

const requests = require("./requests");

const fetchByPid = pid => {
  var dir = "./download/" + pid.toString();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir);
  }
  Promise.all([
    requests.fetchBehavior(pid),
    // requests.fetchPcap(pid),
    // requests.fetchSummary(pid)
  ])
    .then(res => {
      console.log("fetch ..", pid, "done");
    })
    .catch(err => {
      console.log(err);
    });
};

fetchByPid(17784);
