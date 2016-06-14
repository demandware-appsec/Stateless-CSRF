#!/bin/bash

if [ "$TRAVIS_REPO_SLUG" == "demandware-appsec/Stateless-CSRF" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_BRANCH" == "master" ]; then

  echo -e "Creating jar file"
  mvn -f stateless-csrf/pom.xml install

  echo -e "Publishing jar for $TRAVIS_JDK_VERSION"
  jdkver=$(echo -n $TRAVIS_JDK_VERSION | tail -c 4)

  mkdir $HOME/jar-latest/
  cp stateless-csrf/target/*.jar $HOME/jar-latest/
  echo -e "Copied jar"

  cd $HOME
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "travis-ci"
  git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/demandware-appsec/Stateless-CSRF gh-pages > /dev/null
  echo -e "Cloned gh-pages"

  cd gh-pages
  mkdir ./jar/$jdkver/
  cp $HOME/jar-latest/*.jar ./jar/$jdkver/
  git add -f .
  git commit -m "Updating jars on successful travis build $TRAVIS_BUILD_NUMBER auto-pushed to gh-pages"
  git push -fq origin gh-pages > /dev/null
  echo -e "Published Jar to gh-pages.\n"

fi