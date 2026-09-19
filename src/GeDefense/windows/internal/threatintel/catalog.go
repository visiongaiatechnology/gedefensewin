// STATUS: DIAMANT VGT SUPREME
package threatintel

const defaultMaximumFeedBytes int64 = 8 << 20

var catalog = []Source{
	{Key: "feodo", Name: "Feodo Tracker C2", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Format: FormatPlain, Action: ActionBlock, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "spamhaus_drop_v4", Name: "Spamhaus DROP IPv4", URL: "https://www.spamhaus.org/drop/drop_v4.json", Format: FormatNDJSON, Action: ActionBlock, MaximumBytes: defaultMaximumFeedBytes, RequiresMetadata: true},
	{Key: "spamhaus_drop_v6", Name: "Spamhaus DROP IPv6", URL: "https://www.spamhaus.org/drop/drop_v6.json", Format: FormatNDJSON, Action: ActionBlock, MaximumBytes: defaultMaximumFeedBytes, RequiresMetadata: true},
	{Key: "cins_army", Name: "CINS Army Badguys", URL: "https://cinsscore.com/list/ci-badguys.txt", Format: FormatPlain, Action: ActionCorrelateOnly, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "blocklist_de", Name: "blocklist.de All", URL: "https://lists.blocklist.de/lists/all.txt", Format: FormatPlain, Action: ActionCorrelateOnly, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "emerging_threats", Name: "Emerging Threats Block IPs", URL: "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", Format: FormatPlain, Action: ActionCorrelateOnly, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "ipsum", Name: "IPsum Level 1+", URL: "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", Format: FormatPlain, Action: ActionCorrelateOnly, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "firehol_l1", Name: "FireHOL Level 1", URL: "https://iplists.firehol.org/files/firehol_level1.netset", Format: FormatPlain, Action: ActionCorrelateOnly, MaximumBytes: defaultMaximumFeedBytes},
	{Key: "tor_exit", Name: "Tor Exit Nodes", URL: "https://check.torproject.org/torbulkexitlist", Format: FormatPlain, Action: ActionAnnotateOnly, MaximumBytes: defaultMaximumFeedBytes},
}

func Catalog() []Source {
	result := make([]Source, len(catalog))
	copy(result, catalog)
	return result
}

func sourceByKey(key string) (Source, bool) {
	for _, source := range catalog {
		if source.Key == key {
			return source, true
		}
	}
	return Source{}, false
}
