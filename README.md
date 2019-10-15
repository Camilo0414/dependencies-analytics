# Dependencies-Analytics #

Dependencies Analytics is a tool to scan different dependencies files such as pom.xml (Maven) or package.json (NPM) for vulnerabilities.

The first version only generates a CSV file from a set of dependency files.

The tool reads the files from the ```dependencyFiles/``` folder. They should be stored the following way:

```
|-- dependencyFiles
  |-- project1
    |-- dependencyFile1
    |-- dependencyFile2
  - project2
  - project3
  - ...
```
## Vulnerability Check ##

For next iteration it is intended to call the SonaType OSS Index REST API to identify if one of the dependencies has a known vulnerability. The following is the SonaType OSS Index documentation page for the free REST API:

```https://ossindex.sonatype.org/rest#/```

The endpoint receives a purl (Package URL) as coordinates parameter in order to search the package:

```https://github.com/package-url/purl-spec```

## Execution ##

To execute this program the files should be in its correct format inside the folder with the name of the project.

First run in the root folder:

```npm install```

Then run:

```npm run test```

And the script should get the Maven and NPM files from the folders and generate a csv report file under the ```report/``` folder

Due to limitations of the vulnerabilities REST API, we need to make calls in a relatively long interval of time. In the function ```parse_files``` there are two ```setTimeout()``` calls that wait 5 minutes before continuing to the next call for a given file. The time between calls can be changed within this ```setTimeout()``` function.