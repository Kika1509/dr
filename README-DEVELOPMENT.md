# KMS Development, Build, Testing 

## Development

Run the following commands in terminal to start in dev mode.

    ./gradlew
	
## Build properties

* mode: 
    * -Pprod 
    * -Pdev
* version suffix:
    * -PversionSuffix=SNAPSHOT
    * -PversionSuffix=RELEASE

## Building for production

To optimize the kms application for production, run:

    ./gradlew -Pprod clean bootRepackage

To ensure everything worked, run from package modules:

    java -jar build/libs/*.war

or

    java -jar build/libs/*.jar

Then navigate to [http://localhost:8080/kms](http://localhost:8080/kms) in your browser.


## Building before commit

Do build with 

    ./gradlew clean build jacocoTestReport javadoc


## Testing

To launch your application's tests, run:

    ./gradlew test
    
## Using Docker to simplify development (optional)

You can use Docker to improve your development experience. A number of docker-compose configuration are available in the [src/main/docker](src/main/docker) folder to launch required third party services.
For example, to start a mariadb database in a docker container, run:

    docker-compose -f kms-package-jar/src/main/docker/mariadb.yml up -d

To stop it and remove the container, run:

    docker-compose -f kms-package-jar/src/main/docker/mariadb.yml down

You can also fully dockerize your application and all the services that it depends on.
To achieve this, first build a docker image of your app by running (this copies all docker files and jars to build/docker dir and then starts and then starts docker build):

    ./gradlew clean bootRepackage -Pprod buildDocker

Docker is implicitly build with following (this is substep from previous gradle statement that makes docker build):

    docker build -f kms-package-jar/build/docker/Dockerfile -t kms kms-package-jar/build/docker/

After there is Docker image build, then run:

    docker-compose -f kms-package-jar/src/main/docker/app.yml up -d


### Docker and proxy

On windows try to create docker-machine using following steps:

    docker-machine rm default
    docker-machine create -d virtualbox --engine-env HTTP_PROXY=http://<username>:<password>@proxy.kapsch.co.at:8080 --engine-env HTTPS_PROXY=https://<username>:<password>@proxy.kapsch.co.at:8080 --engine-env NO_PROXY=localhost,10.*,192.168.115.*,192.168.99.*,192.168.56.* default

## Using SonarCube from Docker

You can use SonarCube server by using:

    docker-compose -f kms-core/src/main/docker/sonar.yml up
    
and then start:

    ./gradlew sonar
    
The Sonar reports will be available at: http://localhost:9000


## Generation of PDF or HTML from md file

    markdown-pdf /path/to/markdown
    markdown README-USAGE.md > README-USAGE.html
    
### Installation

    npm install markdown-pdf -g
    npm install markdown-to-html -g
