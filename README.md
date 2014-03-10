# Introduction

nxtool is a whitelist generation tool for naxsi.
It provides the following features :
  * Generating whitelists, based on templates, along with "rating"
  * Providing minimal statistics aiming at helping user in whitelist choices
  * Tag existing events matching provided whitelists for exclusion of whitelist generation
  * Tag existing events matching provided IPs for exclusion of whitelist generation

Tagging is important as it will exclude events from whitelist generation process and provide tracking.

# Usage

## Scope/Filtering options

`-s SERVER, --server=SERVER`


## Whitelist generation options

`-t TEMPLATE, --template=TEMPLATE`

Given a path to a template file, attempt to generate matching whitelists.
Possible whitelists will be tested versus database, only the ones with "good" scores will be kept.

`-f, --full-auto`

Attempts whitelist generation for all templates present in rules_path.

`--slack`

Sets nxtool to ignore scores and display all generated whitelists.


## Tagging options

`-w WL_FILE, --whitelist-path=WL_FILE`

Given a whitelist file, finds matching events in database.

`-i IPS, --ip-path=IPS`

Given a list of ips (separatated by \n), finds matching events in database.

`--tag`

Performs the actual tagging. If not specified, matching events are simply displayed.


## Statistics generation options

`-x, --stats`

Generate statistics about current's db content.


# Rating system

  * rule_ip_count : nb of peers hitting rule
  * rule_uri_count : nb of uri the rule hitted on
  * template_ip_count : nb of peers hitting template
  * template_uri_count : nb of uri the rule  hitted on
  * ip_ratio_template : ratio of peers hitting the template vs peers hitting the rule
  * uri_ratio_template : ratio of uri hitting the template vs uri hitting the rule
  * ip_ratio_global : ratio of peers hitting the rule vs all peers
  * uri_ratio_global : ratio of uri hitting the rule vs all uri

# Terms

## Whitelist

A valid naxsi whitelist, ie. `BasicRule wl:X "mz:ARGS";`

## Template

A template for whitelist generation, ie. 

`
{
"zone" : "HEADERS",
"var_name" : "cookie",
"id" : "?"}
`

This template means that nxapi will extract all possible rule IDs found in zone ̀$HEADERS_VAR:cookie`,
and attempt to generate whitelists from it :

`
BasicRule wl:X "mz:$HEADERS_VAR:cookie";
..
`

templates so far support :
  * `"key" : "?"` : Expand key values to all values matching other template's criterias.
    keep in mind that having several '?' fields will seriously increase processing time `(uniques(key1) * uniques(key2) ..)`
  * `"?key" : ".*p.*w.*d.*"` : Expand key values to all values matching regex.
    In outputed rule, `key` is set to matching data, `BasicRule wl:X "mz:$BODY_VAR:user_password";`
  * `_statics : { "id" : "0" }` : If '_statics' is present, it will override fields values in final rule.
  * `_success : {}` and `_warnings : {}` : _success and _warning allow to expand ratings rules.



