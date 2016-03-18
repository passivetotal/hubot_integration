# Description:
#   Bring PassiveTotal data directly into your chats using this Hubot integration.
#
# Dependencies:
#   None
#
# Configuration:
#   PASSIVETOTAL_USERNAME - Email address
#   PASSIVETOTAL_KEY - Sign up at https://www.passivetotal.org/register
#
# Commands:
#   hubot   pt show username - Get the current username value
#   hubot   pt show api key - Get the current API key value
#   hubot   pt set username to <value> - Set the username
#   hubot   pt set api key to <value> - Set the API key
#   hubot   pt set auth to <username:api_key> - Set both username and API key
#   hubot   pt classification for <value> - Get the classification for the value
#   hubot   pt classify <value> as <malicious|suspicious|non-malicious|unknown> - Classify the value
#   hubot   pt is <value> <a sinkhole|sinkholed> - Determine if an IP is a sinkhole
#   hubot   pt is <value> <dyn|dynamic|a dynamic provider|a dyn provider> - Determine if domain is dynamic DNS
#   hubot   pt has <value> <ever been compromised|been compromised> - Determine if value has been compromised
#   hubot   pt show me tags for <value> - Get the tags for the value
#   hubot   pt tag <value> <with|as> <tag> - Add tag value
#   hubot   pt remove <tag> from <value> - Remove add value
#   hubot   pt enrich <value> - Get metadata
#   hubot   pt pdns <value - Get passive results for a domain or IP
#   hubot   pt updns <value> - Get unique resolves for a domain or IP
#   hubot   pt trackers <value> - Get trackers for a domain or IP
#   hubot   pt ssl <value> - Get certificate details for a SHA-1
#   hubot   pt pssl <value> - Get SSL history for an IP or SHA-1
#   hubot   pt whois <value> - Get WHOIS details for a domain or IP
#   hubot   pt osint <value> - Get OSINT reports matching a domain or IP
#   hubot   pt malware <value> - Get malware samples associated with a domain or IP
#   hubot   pt subdomains <value> - Get a list of subdomains for a domain
#
# Author:
#   Brandon Dixon <brandon@passivetotal.org>

PASSIVETOTAL_USERNAME = process.env.PASSIVETOTAL_USERNAME
PASSIVETOTAL_KEY = process.env.PASSIVETOTAL_KEY
PASSIVETOTAL_API = "https://api.passivetotal.org/v2/"

build_url = (slug) ->
    return PASSIVETOTAL_API + slug

printLine = (line) -> process.stdout.write line + '\n'

PT_METADATA_URL = build_url("enrichment")
PT_PASSIVE_DNS_URL = build_url("dns/passive")
PT_SUBDOMAIN_URL = build_url("enrichment/subdomains")
PT_UNIQUE_DNS_URL = build_url("dns/passive/unique")
PT_PASSIVE_SSL_URL = build_url("ssl-certificate/history")
PT_MALWARE_URL = build_url("enrichment/malware")
PT_OSINT_URL = build_url("enrichment/osint")
PT_SSL_DETAILS_URL = build_url("ssl-certificate")
PT_WHOIS_URL = build_url("whois")
PT_TRACKERS_URL = build_url("host-attributes/trackers")
PT_CLASSIFICATION_URL = build_url("actions/classification")
PT_TAGS_URL = build_url("actions/tags")
PT_SINKHOLE_URL = build_url("actions/sinkhole")
PT_DYNAMIC_URL = build_url("actions/dynamic-dns")
PT_EVER_COMPROMISED_URL = build_url("actions/ever-compromised")

positive_findings = ["Appears so!", "Last I checked", "Yes", "Indeed", "Yeah buddy!"]
negative_findings = ["No", "Nope", "Not from what I can see", "Negative", "Nah"]
no_findings = ["Hmm, nothing found!", "Ive got nothing", "No useful results, sorry"]
success_answers = ["Success!", "All done", "You got it", "Roger that", "Okay", "Alright"]

get_data = (robot, url, payload, callback) ->
    response = {'success': false, 'message': ''}
    auth = 'Basic ' + new Buffer(PASSIVETOTAL_USERNAME + ':' + PASSIVETOTAL_KEY).toString('base64');
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    if !PASSIVETOTAL_USERNAME || !PASSIVETOTAL_KEY
        response.message = "You need to set your username and API key before I can run any commands!"
        callback(response)
    robot.http(url + payload)
    .headers(Authorization: auth)
    .get() (err, res, body) ->
        switch res.statusCode
            when 200
                json = JSON.parse(body)
                response.message = json
                response.success = true
                callback(response)
            when 400
                json = JSON.parse(body)
                response.message = "#{json.error.message}"
                callback(response)
            when 401
                json = JSON.parse(body)
                response.message = "#{json.error.message}. Your current authentication is #{PASSIVETOTAL_USERNAME}:#{PASSIVETOTAL_KEY}"
                callback(response)
            when 403
                json = JSON.parse(body)
                response.message = "#{json.error.message}"
                callback(response)
            when 500
                response.message = "Hmm, PassiveTotal failed to handle this query! Sorry about that!"
                callback(response)

send_data = (robot, url, payload, callback) ->
    response = {'success': false, 'message': ''}
    auth = 'Basic ' + new Buffer(PASSIVETOTAL_USERNAME + ':' + PASSIVETOTAL_KEY).toString('base64');
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    if !PASSIVETOTAL_USERNAME || !PASSIVETOTAL_KEY
        response.message = "You need to set your username and API key before I can run any commands!"
        callback(response)
    robot.http(url)
    .headers(Authorization: auth, "Content-Type": 'application/json')
    .post(JSON.stringify(payload)) (err, res, body) ->
        switch res.statusCode
            when 200
                json = JSON.parse(body)
                response.message = json
                response.success = true
                callback(response)
            when 400
                json = JSON.parse(body)
                response.message = "#{json.error.message}"
                callback(response)
            when 401
                json = JSON.parse(body)
                response.message = "#{json.error.message}. Your current authentication is #{PASSIVETOTAL_USERNAME}:#{PASSIVETOTAL_KEY}"
                callback(response)
            when 403
                json = JSON.parse(body)
                response.message = "#{json.error.message}"
                callback(response)
            when 500
                response.message = "Hmm, PassiveTotal failed to handle this query! Sorry about that!"
                callback(response)


module.exports = (robot) ->

    robot.hear /show username/i, (msg) ->
        msg.reply "Username set to #{PASSIVETOTAL_USERNAME}"
    robot.hear /show api key/i, (msg) ->
        msg.reply "API key set to #{PASSIVETOTAL_KEY}"
    robot.hear /show auth/i, (msg) ->
        msg.reply "Auth set to #{PASSIVETOTAL_USERNAME}:#{PASSIVETOTAL_KEY}"
    robot.hear /set username (.*)/i, (msg) ->
        PASSIVETOTAL_USERNAME = msg.match[1].toLowerCase()
        msg.reply msg.random success_answers
    robot.hear /set api key (.*)/i, (msg) ->
        PASSIVETOTAL_KEY = msg.match[1].toLowerCase()
        msg.reply msg.random success_answers
    robot.hear /set auth (.*)/i, (msg) ->
        tmp = msg.match[1].toLowerCase().split(':')
        PASSIVETOTAL_USERNAME = tmp[0]
        PASSIVETOTAL_KEY = tmp[1]
        msg.reply msg.random success_answers

    robot.hear /pt classify (.*) as (malicious|non-malicious|suspicious|unknown)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        classification = msg.match[2].toLowerCase()
        data = {"query": "#{encodeURIComponent value}", "classification": "#{encodeURIComponent classification}"}
        api_response = send_data(robot, PT_CLASSIFICATION_URL, data, (api_response) ->
            if api_response.success
                response += "Classification set!"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt classification for (.*)/i, (msg) ->
        response = ""
        re = new RegExp('(\\?|\\!)', "g");
        value = msg.match[1].toLowerCase().replace("http://", "")
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_CLASSIFICATION_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.classification == ''
                    response += "#{value} hasn't been classified yet!"
                else
                    response += "#{value} is classified as #{json.classification}"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt is (.*) (a sinkhole|sinkholed)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_SINKHOLE_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.sinkhole
                    response += msg.random positive_findings
                else
                    response += msg.random negative_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt is (.*) (dyn|dynamic|a dynamic provider|a dyn provider)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_DYNAMIC_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.dynamicDns
                    response += msg.random positive_findings
                else
                    response += msg.random negative_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt has (.*) (ever been compromised|been compromised)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_EVER_COMPROMISED_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.everCompromised
                    response += msg.random positive_findings
                else
                    response += msg.random negative_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt tags for (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_TAGS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                format_tags = json.tags.join(', ')
                response += "Current tags: #{format_tags}"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt tag (.*) (with|as) (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase().replace("http://", "")
        tags = msg.match[3].split(',')
        data = {"query": "#{encodeURIComponent value}", "tags": tags}
        api_response = send_data(robot, PT_TAGS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                printLine(JSON.stringify(json))
                format_tags = json.tags.join(', ')
                response += "Current tags: #{format_tags}"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt enrich (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_METADATA_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                response += "Here's what I know:\n"
                if json.queryType is "domain"
                    response += "*Base domain:* #{json.primaryDomain}\n"
                    response += "*TLD:* #{json.tld}\n"
                    response += "*Dynamic:* #{json.dynamic}\n"
                else
                    response += "*Country:* #{json.country}\n"
                    response += "*AS:* #{json.autonomousSystemNumber}\n"
                    response += "*AS Name:* #{json.autonomousSystemName}\n"
                    response += "*Sinkhole:* #{json.sinkhole}\n"
                    response += "*Netblock:* #{json.network}\n"

                response += "*Ever Compromised:* #{json.everCompromised}\n"
                response += "*Tags:* #{json.tags}"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt pdns (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_PASSIVE_DNS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.totalRecords > 0
                    response += "Here's a snippet of results:\n"
                    response += "*Resolve count:* " + json.totalRecords + "\n"
                    response += "*First seen:* " + json.firstSeen + "\n"
                    response += "*Last seen:* " + json.lastSeen + "\n"
                    for record, i in json.results when i < 10
                        sources = record.source.join(", ")
                        response += "=> #{record.firstSeen}\t#{record.lastSeen}\t#{record.resolve}\t#{sources}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt updns (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_UNIQUE_DNS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.total > 0
                    response += "Here's what I know:\n"
                    for record, i in json.results when i < 10
                        response += "=> #{record}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt pssl (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_PASSIVE_SSL_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.results.length > 0
                    response += "Here's a snippet of results:\n"
                    for record, i in json.results when i < 10
                        ip_addresses = record.ipAddresses.join(", ")
                        response += "=> #{record.firstSeen}\t#{record.lastSeen}\t#{record.sha1}\t#{ip_addresses}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt trackers (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_TRACKERS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.results.length > 0
                    response += "Here's a snippet of results:\n"
                    for record, i in json.results when i < 10
                        response += "=> #{record.firstSeen}\t#{record.lastSeen}\t#{record.hostname}\t#{record.attributeType}\t#{record.attributeValue}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt ssl (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_SSL_DETAILS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                response += "Here are the certificate details:\n"
                for key, value of json
                    if !value
                        continue
                    response += "=> *#{key}:* #{value}\n"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt whois (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}&compact_record=true"
        api_response = get_data(robot, PT_WHOIS_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                nameservers = json.nameServers.join(", ")
                response += "*Email:* #{json.contactEmail}\n"
                response += "*Registrar:* #{json.registrar}\n"
                response += "*WHOIS Server:* #{json.whoisServer}\n"
                response += "*Nameservers:* #{nameservers}\n"
                response += "*Registered:* #{json.registered}\n"
                response += "*Updated:* #{json.registryUpdatedAt}\n"
                response += "*Expires:* #{json.expiresAt}\n"
                response += "*Details*: \n"
                for key, value in json.compact
                    printLine(key)
                    printLine(JSON.stringify(value))
                    items = []
                    for v in value.values
                        locations = v[1].join(', ')
                        items.push("#{v[0]} (#{locations})")
                    joined = items.join(', ')
                    response += "=> *#{key}:* #{joined}\n"
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt subdomains (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_SUBDOMAIN_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.subdomains.length > 0
                    response += "Here's what I know:\n"
                    for record of json.subdomains
                        response += "=> #{record}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt malware (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_MALWARE_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.results.length > 0
                    response += "Here's what I know:\n"
                    for record in json.results
                        response += "=> #{record.sample} was collected on #{record.collectionDate} from #{record.source}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )

    robot.hear /pt osint (.*)/i, (msg) ->
        response = ""
        value = msg.match[1].toLowerCase()
        data = "?query=#{encodeURIComponent value}"
        api_response = get_data(robot, PT_OSINT_URL, data, (api_response) ->
            if api_response.success
                json = api_response.message
                if json.results.length > 0
                    response += "Here's what I know:\n"
                    for record in json.results
                        response += "=> Mentioned by #{record.source} in #{record.sourceUrl} - #{record.tags}\n"
                else
                    response += msg.random no_findings
            else
                response += api_response.message

            msg.send response
        )