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
    requests.fetchPcap(pid),
    requests.fetchSummary(pid)
  ])
    .then(values => {
      console.log("fetch ..", pid, "done");
      fs.writeFile(
        "./download/" +
        pid.toString() +
          "/" +
          "reports_" +
          pid.toString() +
          ".json",
        JSON.stringify({
          name: pid,
          summary: values[2],
          syscalls: values[0],
        }),
        function(err) {
          if (err) {
            return console.log(err);
          }
          console.log("The file was saved!");
        }
      );
    })
    .catch(err => {
      console.log(err);
    });
};
/////////////////////////////////
//// main
try {
  fetchByPid(process.argv[2]);
} catch (error) {
  console.log(error);
}

// console.log();