import logging
import json
import copy
import operator
import os
import pprint
import shlex
import datetime
import glob


class NxConfig():
    """ Simple configuration loader """
    cfg = {}
    def __init__(self, fname):
        try:
            self.cfg = (json.loads(open(fname).read()))
        except:
            logging.critical("Unable to open/parse configuration file.")
            raise ValueError

class NxRating():
    """ A class that is used to check success criterias of rule.
    attempts jit querying + caching """
    def __init__(self, cfg, es, tr):
        self.tr = tr
        self.cfg = cfg
        self.es = es
        self.esq = {
            'global' : None,
            'template' : None,
            'rule' : None}
        self.stats = {
            'global' : {},
            'template' : {},
            'rule' : {}
            }
        self.global_warnings = cfg["global_warning_rules"]
        self.global_success = cfg["global_success_rules"]
    def drop(self):
        """ clears all existing stats """
        self.stats['template'] = {}
        self.stats['global'] = {}
        self.stats['rule'] = {}
    def refresh_scope(self, scope, esq):
        """ drops all datas for a named scope """
        if scope not in self.esq.keys():
            print "Unknown scope ?!"+scope
        self.esq[scope] = esq
        self.stats[scope] = {}
    def query_ratio(self, scope, scope_small, score, force_refresh):
        """ wrapper to calculate ratio between two vals, rounded float """
        #print "ratio :"+str(self.get(scope_small, score))+" / "+str( self.get(scope, score))
        ratio =  round( (float(self.get(scope_small, score)) / self.get(scope, score)) * 100.0, 2)
        return ratio
    def get(self, scope, score, scope_small=None, force_refresh=False):
        """ fetch a value from self.stats or query ES """
        #print "#GET:"+scope+"_?"+str(scope_small)+"?_"+score+" = ?"
        if scope not in self.stats.keys():
            #print "unknown scope :"+scope
            return None
        if scope_small is not None:
            return self.query_ratio(scope, scope_small, score, force_refresh)
        elif score in self.stats[scope].keys() and force_refresh is False:
            return self.stats[scope][score]
        else:
            if score is not 'total':
                self.stats[scope][score] = self.tr.fetch_uniques(self.esq[scope], score)['total']
            else:
                #self.stats[scope][score] = self.es.search(self.esq[scope])['hits']['total']
#                print "REQ:",
#                pprint.pprint(self.esq[scope])
                res = self.tr.search(self.esq[scope])
#                pprint.pprint(res)
                self.stats[scope][score] = res['hits']['total']
            
            return self.stats[scope][score]
    def check_rule_score(self, tpl):
        """ wrapper to check_score, TOFIX ? """
        return self.check_score(tpl_success=tpl.get('_success', None), tpl_warnings=tpl.get('_warnings', None))
    def check_score(self, tpl_success=None, tpl_warnings=None):
        # g_success_cpt = 0
        # g_warning_cpt = 0
        # tpl_success_cpt = 0
        # tpl_warning_cpt = 0
        success = []
        warning = []
        glb_success = self.global_success
        glb_warnings = self.global_warnings
        if glb_success is not None:
            # print "GLOBAL SUCCESS:",
            # pprint.pprint(glb_success)
            for k in glb_success.keys():
                res = self.check_rule(k, glb_success[k])
                if res['check'] is True:
                    success.append({'key' : k, 'criteria' : glb_success[k], 'curr' : res['curr']})
        if glb_warnings is not None:
            # print "GLOBAL WARNINGS:",
            # pprint.pprint(glb_success)
            for k in glb_warnings.keys():
                res =  self.check_rule(k, glb_warnings[k])
                if res['check'] is True:
                    warning.append({'key' : k, 'criteria' : glb_warnings[k], 'curr' : res['curr']})
        if tpl_success is not None:
            # print "TPL SUCCESS:",
            # pprint.pprint(glb_success)
            for k in tpl_success.keys():
                res = self.check_rule(k, tpl_success[k])
                if res['check'] is True:
                    success.append({'key' : k, 'criteria' : tpl_success[k], 'curr' : res['curr']})
        if tpl_warnings is not None:
            # print "TPL WARNINGS:",
            # pprint.pprint(glb_success)
            for k in tpl_warnings.keys():
                res = self.check_rule(k, tpl_warnings[k])
                if res['check'] is True:
                    warning.append({'key' : k, 'criteria' : tpl_warnings[k], 'curr' : res['curr']})
        x = { 'success' : success,
                 'warnings' : warning }
        # print "CHECK_SCORE RESULTS :",
        # pprint.pprint(x)
        return x
    def check_rule(self, label, check_rule):
        """ check met/failed success/warning criterias
        of a given template vs a set of results """
        #pprint.pprint(check_rule)
        check = check_rule[0]
        beat = check_rule[1]
        
        items = label.split('_')
        #print "label :"+label+":",
        if len(items) == 2:
            scope = items[0]
            score = items[1]
            x = self.get(scope, score)
            #print "curr:"+str(x)+",target:"+str(beat)
            return {'curr' : x, 'check' : check(self.get(scope, score), beat)}
        elif len(items) == 4:
#            print "RATIO !!"
            scope = items[0]
            scope_small = items[1]
            score = items[2]
            x = self.get(scope, score, scope_small=scope_small)
            return {'curr' : x, 'check' : check(self.get(scope, score, scope_small=scope_small), beat)}
        #return check(self.get(scope, score, scope_small=scope_small), beat)
        else:
            print "cannot understand rule ("+label+"):",
            pprint.pprint(check_rule)
            return { 'curr' : 0, 'check' : False }

class NxTranslate():
    """ Transform Whitelists, template into
    ElasticSearch queries, and vice-versa, conventions :
    esq : elasticsearch query
    tpl : template
    cr : core rule
    wl : whitelist """
    def __init__(self, es, cfg):
        self.es = es
        self.debug = True
        self.cfg = cfg.cfg
        self.cfg["global_warning_rules"] = self.normalize_checks(self.cfg["global_warning_rules"])
        self.cfg["global_success_rules"] = self.normalize_checks(self.cfg["global_success_rules"])
        self.core_msg = {}
        # by default, es queries will return 1000 results max
        self.es_max_size = self.cfg.get("elastic").get("max_size", 1000)
        print "# size :"+str(self.es_max_size)
        # purely for output coloring
        self.red = '{0}'
        self.grn = '{0}'
        self.blu = '{0}'
        if self.cfg["output"]["colors"] == "true":
            self.red = "\033[01;31m{0}\033[00m"
            self.grn = "\033[1;36m{0}\033[00m"
            self.blu = "\033[1;94m{0}\033[00m"
        # Attempt to parse provided core rules file
        self.load_cr_file(self.cfg["naxsi"]["rules_path"])

    def full_auto(self):
        """ Loads all tpl within template_path
        If templates has hit, peers or url(s) ratio > 15%,
        attempts to generate whitelists.
        Only displays the wl that did not raise warnings, ranked by success"""
        
        # gather total IPs, total URIs, total hit count
        scoring = NxRating(self.cfg, self.es, self)
        
        strict = True
        if self.cfg.get("naxsi").get("strict", "") == "false":
            strict = False

        scoring.refresh_scope("global", self.cfg["global_filters"])
        if scoring.get("global", "ip") <= 0:
            print "No hits for this filter."
            return
        
        for root, dirs, files in os.walk(self.cfg["naxsi"]["template_path"]):
            for file in files:
                if file.endswith(".tpl"):
                    print "# "+self.grn.format(" template :")+root+"/"+file+" "
                    template = self.load_tpl_file(root+"/"+file)
                    scoring.refresh_scope('template', self.tpl2esq(template))
                    print "Nb of hits :"+str(scoring.get('template', 'total'))
                    if scoring.get('template', 'total') > 0:
                        print self.grn.format("#  template matched, generating all rules.")
                        whitelists = self.gen_wl(template, rule={})
                        print str(len(whitelists))+" whitelists ..."
                        for genrule in whitelists:
                            scoring.refresh_scope('rule', genrule['rule'])
                            results = scoring.check_rule_score(template)
                            if len(results['success']) > 0:
                                print "#some success :)"
                                pprint.pprint(results)
                                print self.grn.format(self.tpl2wl(genrule['rule'])).encode('utf-8')
                                

    def expand_tpl_path(self, template):
        """ attempts to convert stuff to valid tpl paths.
        if it starts with / or . it will consider it's a relative/absolute path,
        else, that it's a regex on tpl names. """
        clean_tpls = []
        tpl_files = []
        if template.startswith('/') or template.startswith('.'):
            tpl_files.extend(glob.glob(template))
        else:
            tpl_files.extend(glob.glob(self.cfg['naxsi']['template_path'] +"/"+template))
        for x in tpl_files:
            if x.endswith(".tpl") and x not in clean_tpls:
                clean_tpls.append(x)
        return clean_tpls

    def load_tpl_file(self, tpl):
        """ open, json.loads a tpl file,
        cleanup data, return dict. """
        try:
            x = open(tpl)
        except:
            logging.error("Unable to open tpl file.")
            return None
        tpl_s = ""
        for l in x.readlines():
            if l.startswith('#'):
                continue
            else:
                tpl_s += l
        try:
            template = json.loads(tpl_s)
        except:
            logging.error("Unable to load json from '"+tpl_s+"'")
            return None
        if '_success' in template.keys():
            template['_success'] = self.normalize_checks(template['_success'])
        if '_warning' in template.keys():
            template['_warning'] = self.normalize_checks(template['_warning'])
        #return self.tpl_append_gfilter(template)
        return template
    def load_wl_file(self, wlf):
        """ Loads a file of whitelists,
        convert them to ES queries, 
        and returns them as a list """
        esql = []
        try:
            wlfd = open(wlf, "r")
        except:
            logging.error("Unable to open whitelist file.")
            return None
        for wl in wlfd:
            [res, esq] = self.wl2esq(wl)
            if res is True:
                esql.append(esq)
        if len(esql) > 0:
            return esql
        return None
    def load_cr_file(self, cr_file):
        """ parses naxsi's core rule file, to
        decorate output with "msg:" field content """
        core_msg = {}
        core_msg['0'] = "id:0 is wildcard (all rules) whitelist."
        try:
            fd = open(cr_file, 'r')
            for i in fd:
                if i.startswith('MainRule') or i.startswith('#@MainRule'):
                    pos = i.find('id:')
                    pos_msg = i.find('msg:')
                    self.core_msg[i[pos + 3:i[pos + 3].find(';') - 1]] = i[pos_msg + 4:][:i[pos_msg + 4:].find('"')]
            fd.close()
        except:
            logging.error("Unable to open rules file")
    def tpl2esq(self, ob, full=True):
        ''' receives template or a rule, returns a valid 
        ElasticSearch query '''
        qr = { 
            "query" : { "bool" : { "must" : [ ]} },
            "size" : self.es_max_size
            }
        # A hack in case we were inadvertently given an esq
        if 'query' in ob.keys():
            return ob
        for k in ob.keys():
            if k.startswith("_"):
                continue
            # if key starts with '?' :
            # use content for search, but use content from exceptions to generate WL
            if k[0] == '?':
                k = k[1:]
                qr['query']['bool']['must'].append({"regexp" : { k : ob['?'+k] }})
            # wildcard
            elif ob[k] == '?':
                pass
            else:
                qr['query']['bool']['must'].append({"text" : { k : ob[k]}})

        qr = self.append_gfilter(qr)
        return qr
    def append_gfilter(self, esq):
        """ append global filters parameters 
        to and existing elasticsearch query """
        for x in self.cfg["global_filters"]:
            if {"text" : { x : self.cfg["global_filters"][x] }} not in esq['query']['bool']['must']:
                esq['query']['bool']['must'].append({"text" : { x : self.cfg["global_filters"][x] }})
            # else:
            #     print "double!"
        return esq
    def tpl_append_gfilter(self, tpl):
        for x in self.cfg["global_filters"]:
            tpl[x] = self.cfg["global_filters"][x]
        return tpl
    def wl2esq(self, raw_line):
        """ parses a fulltext naxsi whitelist,
        and outputs the matching es query (ie. for tagging),
        returns [True|False, error_string|ESquery] """
        esq = { 
            "query" : { "bool" : { "must" : [ ]} },
            "size" : self.es_max_size
            }
        wl_id = ""
        mz_str = ""
        # do some pre-check to ensure it's a valid line
        if raw_line.startswith("#"):
            return [False, "commented out"]
        if raw_line.find("BasicRule") == -1:
            return [False, "not a BasicRule"]
        # split line
        strings = shlex.split(raw_line)
        # more checks
        if len(strings) < 3:
            return [False, "empty/incomplete line"]
        if strings[0].startswith('#'):
            return [False, "commented line"]
        if strings[0] != "BasicRule":
            return [False, "not a BasicRule, keyword '"+strings[0]+"'"]
        if strings[len(strings) - 1].endswith(';'):
            strings[len(strings) - 1] = strings[len(strings) - 1][:-1]
        for x in strings:
            if x.startswith("wl:"):
                wl_id = x[3:]
                # if ID contains "," replace them with OR for ES query
                wl_id = wl_id.replace(",", " OR ")
                # if ID != 0 add it, otherwise, it's a wildcard!
                if wl_id != "0":
                    # if IDs are negative, we must exclude all IDs except
                    # those ones.
                    if wl_id.find("-") != -1:
                        wl_id = wl_id.replace("-", "")
                        #print "Negative query."
                        if not 'must_not' in tpl['query']['bool'].keys():
                            esq['query']['bool']['must_not'] = []
                        esq['query']['bool']['must_not'].append({"text" : { "id" : wl_id}})
                    else:
                        esq['query']['bool']['must'].append({"text" : { "id" : wl_id}})
            if x.startswith("mz:"):
                mz_str = x[3:]
                [res, filters] = self.parse_mz(mz_str, esq)
                if res is False:
                    #print "mz parse failed : "+str(filters)
                    return [False, "matchzone parsing failed."]
        #print "#rule: "+raw_line
        #pprint.pprint(filters)
        esq = self.append_gfilter(esq)
        #print "##after :"
        #pprint.pprint(filters)
        return [True, filters]
    def parse_mz(self, mz_str, esq):
        """ parses a match zone from BasicRule, and updates
        es query accordingly """
        kw = mz_str.split("|")
        tpl = esq['query']['bool']['must']
        uri = ""
        zone = ""
        var_name = ""
        t_name = False
        # |NAME flag
        if "NAME" in kw:
            t_name = True
            kw.remove("NAME")
        for k in kw:
            # named var
            if k.startswith('$'):
                k = k[1:]
                try:
                    [zone, var_name] = k.split(':')
                except:
                    return [False, "Incoherent zone : "+k]
                # *_VAR:<string>
                if zone.endswith("_VAR"):
                    zone = zone[:-4]
                    if t_name is True:
                        zone += "|NAME"
                    tpl.append({"text" : { "zone" : zone}})
                    tpl.append({"text" : { "var_name" : var_name}})
                # *_VAR_X:<regexp>
                elif zone.endswith("_VAR_X"):
                    zone = zone[:-6]
                    if t_name is True:
                        zone += "|NAME"
                    tpl.append({"text" : { "zone" : zone}})
                    tpl.append({"regexp" : { "var_name" : var_name}})
                # URL_X:<regexp>
                elif zone == "URL_X":
                    zone = zone[:-2]
                    tpl.append({"regexp" : { "uri" : var_name}})
                # URL:<string>
                elif zone == "URL":
                    tpl.append({"text" : { "uri" : var_name }})
                else:
                    print "huh, what's that ? "+zone

            # |<ZONE>
            else:
                if k not in ["HEADERS", "BODY", "URL", "ARGS"]:
                    return [False, "Unknown zone : '"+k+"'"]
                zone = k
                if t_name is True:
                    zone += "|NAME"
                tpl.append({"text" : {"zone" : zone}})
        return [True, esq]
    def tpl2wl(self, rule):
        """ transforms a rule/esq
        to a valid BasicRule. """
        tname = False
        zone = ""

        wl = "BasicRule "
        wl += " wl:"+str(rule.get('id', 0)).replace("OR", ",").replace("|", ",").replace(" ", "")

        wl += ' "mz:'

        if rule.get('uri', None) is not None:
            wl += "$URL:"+rule['uri']
            wl += "|"
        # whitelist targets name    
        if rule.get('zone', '').endswith("|NAME"):
            tname = True
            zone = rule['zone'][:-5]
        else:
            zone = rule['zone']

        if rule.get('var_name', '') not in  ['', '?']:
            wl += "$"+zone+"_VAR:"+rule['var_name']
        else:
            wl += zone

        if tname is True:
            wl += "|NAME"

        wl += '";'
        return wl
    #def check_criterias(self, template, , stats, results):
    #pass
    def check_success(self, rule, stats):
        """ check met/failed success/warning criterias
        of a given template vs a set of results """
        score = 0
        warnings = 0

        # Check as rule's specific warning criterias
        if '_warning' in rule.keys():
            for sucrule in rule['_warning'].keys():
                if sucrule not in stats.keys():
                    continue
                else:
                    if rule['_warning'][sucrule][0](stats[sucrule], rule['_warning'][sucrule][1]) is True:
                        warnings += 1
        # Check success rules, and increase score if conditions are met.
        if '_success' in rule.keys():
            for sucrule in rule['_success'].keys():
                if sucrule not in stats.keys():
                    continue
                else:
                    if rule['_success'][sucrule][0](stats[sucrule], rule['_success'][sucrule][1]) is True:
                        score += 1

        # Check generic success rules and generic warnings
        for sucrule in self.cfg["global_warning_rules"].keys():
            if sucrule not in stats.keys():
                continue
            else:
                if self.cfg["global_warning_rules"][sucrule][0](stats[sucrule], self.cfg["global_warning_rules"][sucrule][1]) is True:
                    warnings += 1

        # Check generic success rules and generic warnings
        for sucrule in self.cfg["global_success_rules"].keys():
            if sucrule not in stats.keys():
                continue
            else:
                if self.cfg["global_success_rules"][sucrule][0](stats[sucrule], self.cfg["global_success_rules"][sucrule][1]) is True:
                    score += 1
        return { 'success' : score, 'warning' : warnings }
    def fetch_top(self, template, field, limit=10):
        """ fetch top items for a given field,
        clears the field if exists in gfilters """
        x = None
        if field in template.keys():
            x = template[field]
            del template[field]
        esq = self.tpl2esq(template)
        if x is not None:
            template[field] = x
        esq['facets'] =  { "facet_results" : {"terms": { "field": field, "size" : self.es_max_size} }}
        res = self.search(esq)
        total = res['facets']['facet_results']['total']
        count = 0
        for x in res['facets']['facet_results']['terms']:
            print "# "+self.grn.format(x['term'])+" "+str(round( (float(x['count']) / total) * 100.0, 2))+" % (total:"+str(x['count'])+"/"+str(total)+")"
            count += 1
            if count > limit:
                break
    def fetch_uniques(self, rule, key):
        """ shortcut function to gather unique
        values and their associated match count """
        # print "fetch_uniques :",
        # pprint.pprint(rule)
        uniques = []
        #print "req:",
        #pprint.pprint(rule)
        esq = self.tpl2esq(rule)
        esq['facets'] =  { "facet_results" : {"terms": { "field": key, "size" : 50000} }}
        #res = self.es.search(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=esq)
        res = self.search(esq)
        #pprint.pprint(res)
        for x in res['facets']['facet_results']['terms']:
            uniques.append(x['term'])
        #print "UNIQUES LEN:"+str(len(uniques)),
        #pprint.pprint(uniques)
        return { 'list' : uniques, 'total' :  len(uniques) }
    def index(self, body, eid):
        return self.es.index(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=body, id=eid)
    def search(self, esq, stats=False):
        """ search wrapper with debug """
        debug = False
        
        if debug is True:
            print "#SEARCH:PARAMS:index="+self.cfg["elastic"]["index"]+", doc_type="+self.cfg["elastic"]["doctype"]+", body=",
            print "#SEARCH:QUERY:",
            pprint.pprint (esq)
        if len(esq["query"]["bool"]["must"]) == 0:
            del esq["query"]
        x = self.es.search(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=esq)
        if debug is True:
            print "#RESULT:",
            pprint.pprint(x)
        return x
    def normalize_checks(self, tpl):
        """ replace check signs (<, >, <=, >=) by 
                operator.X in a dict-form tpl """
        replace = {
            '>' : operator.gt,
            '<' : operator.lt,
            '>=' : operator.ge,
            '<=' : operator.le
            }
        
        for tpl_key in tpl.keys():
            for token in replace.keys():
                if tpl[tpl_key][0] == token:
                    tpl[tpl_key][0] = replace[token]
        return tpl
    def display_rule(self, ratings, stats, template, content):
        """ displays a given rule+template to BasicRule,
        along with collected statistics """
        tmprule = content["rule"]
        exlog = content["content"]
        uri = content["uri"]
        peers = content["peers"]
        # If at least one warning was triggered, it might be a false positive
        if template is not None and '_statics' in template.keys():
            for k in template['_statics'].keys():
                tmprule[k] = template['_statics'][k]

        print "\n\n"
        if ratings['warning'] > 0:
            print self.red.format("# At least one warning was raised, might be a FP")
            print "# Warnings : "+self.red.format('*' * ( ratings['warning']))
        
        print "# Rating : "+self.grn.format('*' * ( ratings['success'] - ratings['warning']))
        print "# "+str(round(stats['hit_ratio_template'], 2))+"% of (total) evts matched WL ("+str(stats['rule_hits'])+"/"+str(stats['total_hits'])+")"
        print "# "+str(round(stats['ip_ratio_global'], 2))+"% of (total) peers triggered this WL ("+str(stats['rule_ip_count'])+"/"+str(stats['global_ip_count'])+")"
        print "# "+str(round(stats['ip_ratio_template'], 2))+"% of (orig rule) peers triggered this WL ("+str(stats['rule_ip_count'])+"/"+str(stats['template_ip_count'])+")"
        print "# "+str(round(stats['uri_ratio_template'], 2))+"% of (orig rule) URLs triggered this WL ("+str(stats['rule_uri_count'])+"/"+str(stats['template_uri_count'])+")"
        print "# rule: "+self.blu.format(self.core_msg.get(tmprule.get('id', 0), "Unknown"))
        for x in exlog:
            print "# content: "+x.encode('utf-8')
        for x in uri:
            print "# uri: "+x.encode('utf-8')
        for x in peers:
            print "# peers: "+x.encode('utf-8')
        if ratings['success'] > 0:
            print self.grn.format(self.tpl2wl(tmprule)).encode('utf-8')
        else:
            print "# "+self.red.format(self.tpl2wl(tmprule)).encode('utf-8')


    def tag_events(self, esq, msg, tag=False):
        """ tag events with msg + tstamp if they match esq """
        count = 0
        esq["size"] = "0"
        x = self.search(esq)
        print self.grn.format(str(x["hits"]["total"])) + " items to be tagged ..."
        esq["size"] = x["hits"]["total"]
        res = self.search(esq)
        # Iterate through matched evts to tag them.
        for item in res['hits']['hits']:
            eid = item['_id']
            body = item['_source']
            cm = item['_source']['comments']
            body['comments'] += ","+msg+":"+str(datetime.datetime.now())
            body['whitelisted'] = "true"
            if tag is True:
                print "Tagging id: "+eid
                print str(self.index(body, eid))
            else:
                print eid+",",
            count += 1
        print ""
        return count


    def gen_wl(self, tpl, rule={}):
        """ recursive whitelist generation function,
        returns a list of all possible witelists. """
        retlist = []
        for tpl_key in tpl.keys():
            if tpl_key in rule.keys():
                continue
            if tpl_key[0] in ['_', '?']:
                continue
            if tpl[tpl_key] == '?':
                continue
            rule[tpl_key] = tpl[tpl_key]
        for tpl_key in tpl.keys():
            if tpl_key.startswith('_'):
                continue
            elif tpl_key.startswith('?'):
#                print "check if "+tpl_key+" is here :",
                
                if tpl_key[1:] in rule.keys():
 #                   print "yes"
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key[1:])['list']
                for uval in unique_vals:
                    rule[tpl_key[1:]] = uval
                    retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
            elif tpl[tpl_key] == '?':
                if tpl_key in rule.keys():
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key)['list']
                for uval in unique_vals:
                    rule[tpl_key] = uval
                    retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
            elif tpl_key not in rule.keys():
                rule[tpl_key] = tpl[tpl_key]
                retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
    
        esq = self.tpl2esq(rule)
        res = self.search(esq)
        if res['hits']['total'] > 0:
            clist = []
            peers = []
            uri = []
            
            for x in res['hits']['hits']:
                if len(x.get("_source").get("ip", "")) > 0 and x.get("_source").get("ip", "") not in peers:
                    peers.append(x["_source"]["ip"])
                if len(x.get("_source").get("uri", "")) > 0 and x.get("_source").get("uri", "") not in uri:
                    uri.append(x["_source"]["uri"])
                if len(x.get("_source").get("content", "")) > 0 and x.get("_source").get("content", "") not in clist:
                    clist.append(x["_source"]["content"])
                    if len(clist) >= 5:
                        break
            retlist.append({'rule' : rule, 'content' : clist[:5], 'total_hits' : res['hits']['total'], 'peers' : peers[:5], 'uri' : uri[:5]})
            return retlist
        return []
