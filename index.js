const fs = require('fs');
const pom_parser = require("pom-parser");
const util = require('util');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const request = require('request');

const reportFolder = "./report"
if (!fs.existsSync(reportFolder)) {
    fs.mkdirSync(reportFolder)
}

const result_report_filename = "report/dependencies_report.csv";
const vulnerability_api_base_url = "https://ossindex.sonatype.org/api/v3/component-report";

const header_object = [
    { id: 'projectname', title: 'Project Name' },
    { id: "jsondependencyname", title: 'Package JSON Dependency' },
    { id: "jsondevdependencyname", title: 'Package JSON Dev Dependency' },
    { id: 'groupid', title: 'Group ID' },
    { id: 'artifactid', title: 'ArtifactId' },
    { id: 'version', title: 'Version' },
    { id: 'vulnerabilities', title: 'Vulnerabilities' }
]

var csvWriter = createCsvWriter({
    path: result_report_filename,
    header: header_object,
    append: true
});

write_csv_file_headers();
write_dependencies_to_csv();

function write_csv_file_headers() {
    var titles = header_object.map(header => header.title);
    var writable_titles = [];
    writable_titles.push({
        projectname: titles[0],
        jsondependencyname: titles[1],
        jsondevdependencyname: titles[2],
        groupid: titles[3],
        artifactid: titles[4],
        version: titles[5],
        vulnerabilities: titles[6]
    });
    csvWriter.writeRecords(writable_titles);
}

function write_dependencies_to_csv() {
    var path = "dependencyFiles/";
    var projects = fs.readdirSync(path);
    var fileToIgnore = ".DS_Store";
    projects = projects.filter(file => !fileToIgnore.includes(file));

    for (let project of projects) {
        path = "dependencyFiles/" + project + "/";
        var dependencyFiles = fs.readdirSync(path);
        dependencyFiles = dependencyFiles.filter(file => !fileToIgnore.includes(file));
        for (let file of dependencyFiles) {
            var complete_filepath = path + file;
            if (fs.lstatSync(complete_filepath).isDirectory()) {
                var inner_files = fs.readdirSync(complete_filepath);
                for (let inner_file of inner_files) {
                    complete_filepath = path + file;
                    project_information = inner_file.split(".");
                    extension = project_information.pop();
                    filename = project_information.pop();
                    complete_filepath = complete_filepath + "/" + inner_file;
                    parse_files(extension, complete_filepath, filename, project_information);
                }
            } else {
                project_information = file.split(".");
                extension = project_information.pop();
                filename = project_information.pop();
                parse_files(extension, complete_filepath, filename, project_information)
            }
        }
    };
}

function parse_files(extension, complete_filepath, filename, project_information) {
    console.error(extension);
    switch (extension) {
        case "xml":
            setTimeout(parse_pom_file, 150000, complete_filepath, filename);
            break;
        case "json":
            if (filename !== "npm-shrinkwrap" && filename !== "package-lock") {
                setTimeout(parse_json_file, 150000, complete_filepath, filename);
            }
            break;
        default:
            console.log("File extension not supported for: " + project_information);
    }
}

function parse_pom_file(complete_filepath, project_name) {
    var opts = { filePath: complete_filepath };
    // Get pom.xml file to JSON object
    pom_parser.parse(opts, function (err, pom_response) {
        if (err === null) {
            console.log("into if err===null");
            var pom_dependencies = pom_response.pomObject.project.dependencies.dependency;
            console.log(pom_dependencies);
            pom_dependencies = add_project_name(pom_dependencies, project_name);
            let request_body = build_maven_vulnerabilities_request_body(pom_dependencies);
            console.log(request_body);
            console.log(request_body.coordinates.length);
            if (request_body.coordinates.length != 0) {
                // Call SonaType OSS Index
                call_sonatype_endpoint(request_body)
                    .then((dependency_vulnerabilities_list) => {
                        for (let dependency of dependency_vulnerabilities_list) {
                            let dependencyIndex = dependency_vulnerabilities_list.findIndex((array_dependency) => {
                                return dependency.coordinates === array_dependency.coordinates;
                            });
                            if (dependency.vulnerabilities[0] != undefined) {
                                pom_dependencies[dependencyIndex].vulnerabilities = dependency.vulnerabilities[0].description;
                            }
                        }
                        csvWriter.writeRecords(pom_dependencies);
                    })
                    .catch(reason => { console.log(reason); });
            }
        }
    });
}

function parse_json_file(complete_filepath, project_name) {
    let dependency_objects;
    let dev_dependency_objects;
    fs.readFile(complete_filepath, function (err, data) {
        var packageFile = JSON.parse(data.toString());
        var dependencies = Object.entries(packageFile.dependencies);

        dependency_objects = dependencies.map((dependency) => {
            if (dependency[0][0] == "@") dependency[0] = dependency[0].replace("@", "%40");
            return {
                projectname: project_name,
                jsondependencyname: dependency[0],
                version: clean_dependencies_version(dependency)
            }
        });

        if (packageFile.hasOwnProperty("devDependencies")) {
            var dev_dependencies = Object.entries(packageFile.devDependencies);
            dev_dependency_objects = dev_dependencies.map((dev_dependency) => {
                if (dev_dependency[0][0] == "@") dev_dependency[0] = dev_dependency[0].replace("@", "%40");
                return {
                    projectname: project_name,
                    jsondevdependencyname: dev_dependency[0],
                    version: clean_dependencies_version(dev_dependency)
                }
            });
        }

        let npm_dependencies = dependency_objects;
        if (dev_dependency_objects !== undefined) {
            npm_dependencies = dependency_objects.concat(dev_dependency_objects);
        }
        let request_body = build_npm_vulnerabilities_request_body(npm_dependencies);

        if (request_body.coordinates.length != 0) {
            // Call SonaType OSS Index
            console.error(request_body);
            call_sonatype_endpoint(request_body)
                .then((dependency_vulnerabilities_list) => {
                    for (let dependency of dependency_vulnerabilities_list) {
                        let dependencyIndex = dependency_vulnerabilities_list.findIndex((array_dependency) => {
                            return dependency.coordinates === array_dependency.coordinates;
                        });
                        if (dependency.vulnerabilities[0] != undefined) {
                            npm_dependencies[dependencyIndex].vulnerabilities = dependency.vulnerabilities[0].description
                        }
                    }
                    csvWriter.writeRecords(npm_dependencies);
                })
                .catch(reason => { console.log(reason); });
        }
    });
}


function build_maven_vulnerabilities_request_body(pom_dependencies) {
    let vulnerabilities_request_body = [];
    let maven_purl;
    console.log("build_maven....")
    for (const dependency of pom_dependencies) {
        console.log(dependency);
        //Get the index of the dependency in order to add it to the vulnerability request
        let dependencyIndex = pom_dependencies.findIndex(array_dependency => dependency.artifactid === array_dependency.artifactid);

        // Check if the version is null, undefined or a variable in the pom.xml
        if (dependency.version === undefined || dependency.version === null || dependency.version[dependency.version.lastIndexOf("@") + 1] === "$") {
            maven_purl = util.format("pkg:maven/%s/%s@latest", dependency.groupid, dependency.artifactid);
            vulnerabilities_request_body[dependencyIndex] = maven_purl;
        } else {
            maven_purl = util.format("pkg:maven/%s/%s@%s", dependency.groupid, dependency.artifactid, dependency.version);
            vulnerabilities_request_body[dependencyIndex] = maven_purl;
        }
    }
    console.log(vulnerabilities_request_body);
    return {
        "coordinates": vulnerabilities_request_body
    }
}

function build_npm_vulnerabilities_request_body(npm_dependencies) {
    let vulnerabilities_request_body = [];
    let maven_purl;
    for (const dependency of npm_dependencies) {
        let dependencyIndex;
        //Get the index of the dependency in order to add it to the vulnerability request
        if (dependency.jsondevdependencyname != undefined) {
            dependencyIndex = npm_dependencies.findIndex((array_dependency) => {
                return dependency.jsondevdependencyname === array_dependency.jsondevdependencyname;
            });
            maven_purl = util.format("pkg:npm/%s@%s", dependency.jsondevdependencyname, dependency.version);
        } else {
            dependencyIndex = npm_dependencies.findIndex((array_dependency) => {
                return dependency.jsondependencyname === array_dependency.jsondependencyname;
            });
            maven_purl = util.format("pkg:npm/%s@%s", dependency.jsondependencyname, dependency.version);
        }

        vulnerabilities_request_body[dependencyIndex] = maven_purl;
    }

    return {
        "coordinates": vulnerabilities_request_body
    }
}

function call_sonatype_endpoint(coordinates) {
    return requestPromise = new Promise((resolve, reject) => {
        return request.post(vulnerability_api_base_url,
            {
                url: vulnerability_api_base_url,
                json: coordinates
            },
            function (error, response, body) {
                console.log(error);

                if (!error && response.statusCode == 200) {
                    resolve(body);
                } else if (response) {
                    if (response.statusCode == 429 || response.statusCode == 400 || response.statusCode == 500) {
                        console.log("The status cooooooooode is: ")
                        console.log(response.statusCode);
                        console.log(body);
                        reject(new Error(response.statusMessage));
                    }
                }
                reject(new Error("No response"));
            });
    });
}

function clean_dependencies_version(dependency) {
    return dependency[1].replace(/(\^|~|=|<|>)/g, "");
}

function add_project_name(dependencies_list, project_name) {
    dependencies_list.map((dependency) => {
        dependency.projectname = project_name;
        return dependency;
    });
    return dependencies_list;
}
