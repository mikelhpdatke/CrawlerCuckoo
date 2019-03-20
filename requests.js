const fetch = require("node-fetch");
var https = require("https");
const cheerio = require("cheerio");
const fs = require("fs");

var download = function(url, dest, cb) {
  var file = fs.createWriteStream(dest);
  var request = https
    .get(url, function(response) {
      response.pipe(file);
      file.on("finish", function() {
        file.close(cb); // close() is async, call cb after close compvares.
      });
    })
    .on("error", function(err) {
      // Handle errors
      fs.unlink(dest); // Devare the file async. (But we don't check the result)
      if (cb) cb(err.message);
    });
};
const homePage = "https://linux.huntingmalware.com";

const fetchPcap = id =>
  fetch(
    "https://linux.huntingmalware.com/analysis/" + id.toString() + "/network/",
    {
      credentials: "include",
      headers: {
        accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "accept-language":
          "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
        "cache-control": "max-age=0",
        "upgrade-insecure-requests": "1"
      },
      // referrer: "https://linux.huntingmalware.com/analysis/16603/summary/",
      referrerPolicy: "no-referrer-when-downgrade",
      body: null,
      method: "GET",
      mode: "cors"
    }
  )
    .then(ret => ret.text())
    .then(res => {
      const $ = cheerio.load(res);
      var hrefPcap = $("div div article header div a").attr("href");
      download(
        homePage + hrefPcap,
        "./download/" + id.toString() + "/" + id.toString() + ".pcap",
        err => {
          console.log(err);
        }
      );
      return true;
    });

const fetchSummary = id =>
  fetch(
    "https://linux.huntingmalware.com/analysis/" + id.toString() + "/summary/",
    {
      credentials: "include",
      headers: {
        accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "accept-language":
          "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
        "cache-control": "max-age=0",
        "upgrade-insecure-requests": "1"
      },
      referrer: "https://linux.huntingmalware.com/analysis/",
      referrerPolicy: "no-referrer-when-downgrade",
      body: null,
      method: "GET",
      mode: "cors"
    }
  )
    .then(ret => ret.text())
    .then(ret => {
      const $ = cheerio.load(ret);
      var summaryData = {};
      var str = $(".table-striped").each(function(index, table) {
        if (index === 0) {
          $(table)
            .find("tr")
            .each((index, elem) => {
              // console.log(index);
              var name = $(elem)
                .find("th")
                .text();
              var value = $(elem)
                .find("td")
                .text()
                .replace(/\s/g, "");
              // console.log(name,'', value.replace(/\s/g, ""));
              summaryData[name] = value;
            });
        }
      });

      // console.log($('.table-striped').children().text())
      // .replace(/\s/g, ""));
      // fs.writeFile(
      //   "./download/" + id.toString() + "/summary_" + id.toString() + ".json",
      //   JSON.stringify({
      //     name: id.toString(),
      //     data: summaryData,
      //   }),
      //   function(err) {
      //     if (err) {
      //       return console.log(err);
      //       throw new Error(err);
      //     }
      //     //   console.log("The file was saved!");
      //   }
      // );
      return summaryData;
    });

const fetchPreBehavior = id => {
  return fetch(
    "https://linux.huntingmalware.com/analysis/" + id.toString() + "/behavior/",
    {
      credentials: "include",
      headers: {
        accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "accept-language":
          "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
        "cache-control": "max-age=0",
        "upgrade-insecure-requests": "1"
      },
      referrer: "https://linux.huntingmalware.com/analysis/17784/summary",
      referrerPolicy: "no-referrer-when-downgrade",
      body: null,
      method: "GET",
      mode: "cors"
    }
  )
    .then(ret => ret.text())
    .then(res => {
      const $ = cheerio.load(res);
      return $(".pid").text();
    });
};

const fetchBehavior = id => {
  return new Promise(resolve => {
    fetchPreBehavior(id).then(pid => {
      return fetch(
        "https://linux.huntingmalware.com/analysis/chunk/" +
          id.toString() +
          "/" +
          pid.toString() +
          "/1/",
        {
          credentials: "include",
          headers: {
            accept: "*/*",
            "accept-language":
              "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
            "x-requested-with": "XMLHttpRequest"
          },
          referrer: "https://linux.huntingmalware.com/analysis/17784/behavior/",
          referrerPolicy: "no-referrer-when-downgrade",
          body: null,
          method: "GET",
          mode: "cors"
        }
      )
        .then(ret => ret.text())
        .then(ret => {
          const $ = cheerio.load(ret);
          var arrayResult = [];
          $("table tbody")
            .children()
            .each((i, elem) => {
              var result = {};
              $(elem)
                .children()
                .each(function(i, elem) {
                  if (i === 0)
                    result["syscall"] = $(this)
                      .find("p")
                      .text();
                  if (i === 1) {
                    // console.log("--");
                    var str = $(this)
                      .text()
                      .replace(/\s/g, "");
                    var listP = str.match(/p\d:/gm) || [];
                    var mListIndex = listP.map(val => {
                      return str.indexOf(val);
                    });
                    mListIndex.push(str.length);
                    var targetReg = {};
                    for (var i = 0; i < mListIndex.length - 1; i++) {
                      var register = str.substr(
                        mListIndex[i],
                        mListIndex[i + 1] - mListIndex[i]
                      );
                      var nameReg = register.substr(0, 2);
                      var valueReg = register.substr(3, register.length - 3);
                      targetReg[nameReg] = valueReg;
                    }
                    result["params"] = targetReg;
                  }
                });
              arrayResult.push(result);
            });
          resolve({
            name: id,
            data: arrayResult
          });
        });
    });
  });
};

module.exports = {
  fetchSummary,
  fetchPcap,
  fetchBehavior
};
