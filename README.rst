PassiveTotal Hubot Scripts
==========================

Introduction
------------

*Hubot helper scripts for PassiveTotal*

Chat programs like Slack and HipChat are great for collaboration and can greatly help users during incident response scenarios or answering ad-hoc questions about infrastructure. These Hubot scripts bring the data from PassiveTotal directly into your chat channel. These scripts are based on version two of the PassiveTotal API and supports most of the endpoints defined there.

Installation
------------

*In order to run these transforms, you will need to setup a local Hubot instance*

1. Run the following command (**do not use root!**)::

    npm install -g hubot coffee-script yo generator-hubot

2. Make a directory for your bot to live in and change to it::

    mkdir -p /opt/hubot && cd /opt/hubot

3. Setup the bot using yo (**this will fail if you ran with root**) and follow the prompts::

    yo hubot --adapter <slack|hipchat>

4. Save your configuration::

    npm install hubot-<slack|hipchat> --save

5. Get an integration token from your Slack team by creating a bot_.

.. _bot: https://my.slack.com/services/new/bot

6. Start the bot inside a screen or tmux session::

    HUBOT_SLACK_TOKEN=<--YOUR--TOKEN--> ./bin/hubot --adapter slack
    HUBOT_HIPCHAT_JID=<--HIPCHAT-USERNAME--> HUBOT_HIPCHAT_PASSWORD=<--HIPCHAT-PASSWORD--> ./bin/hubot --adapter hubot

7. Authenticate to your bot::

    @botname set auth <username>:<api-key>

8. List the options for interacting::

    @botname help


Support
-------

These scripts come with no support and are only provided as a convenience. If you run into any issues with the specific PassiveTotal coffeescripts, please file an issue and we will help triage the problem.
