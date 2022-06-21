package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	"github.com/sensu/sensu-go/types"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	Binary string
	Sudo   bool
    Config string
}

type UnboundMetric struct {
    metricFamily *dto.MetricFamily
    labels []string
    pattern *regexp.Regexp
}

func newUnboundMetric(name string, help string, metricType dto.MetricType, labels []string, pattern string) *UnboundMetric {
    fullName := fmt.Sprintf("unbound_%s", name)
    return &UnboundMetric{
        metricFamily: &dto.MetricFamily{
            Name: &fullName,
            Help: &help,
            Type: &metricType,
            Metric: []*dto.Metric{},
        },
        labels: labels,
        pattern: regexp.MustCompile(pattern),
    }
}

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "check-unbound",
			Short:    "Simple cross-platform Unbound checks",
			Keyspace: "sensu.io/plugins/check-unbound/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "binary",
			Argument:  "binary",
			Shorthand: "b",
			Default:   "/usr/sbin/unbound-control",
			Usage:     "Location of the unbound-control binary",
			Value:     &plugin.Binary,
		},
		{
			Path:	  "sudo",
			Argument: "sudo",
			Shorthand: "s",
			Default: false,
			Usage: "Execute with root privileges",
			Value:  &plugin.Sudo,
		},
        {
            Path: "config",
            Argument: "config",
            Shorthand: "c",
            Default: "",
            Usage: "Location of the Unbound config file",
            Value: &plugin.Config,
        },
	}

    histogramMetric = newUnboundMetric(
        "response_time_seconds",
        "Query response time in seconds.",
        dto.MetricType_HISTOGRAM,
        []string{},
        "^histogram\\.\\d+\\.\\d+\\.to\\.(\\d+\\.\\d+)$",
    )

    unboundMetrics = []*UnboundMetric{
        newUnboundMetric(
            "answer_rcodes_total",
            "Total number of answers to queries, from cache or from recursion, by response code.",
            dto.MetricType_COUNTER,
            []string{"rcode"},
            "^num\\.answer\\.rcode\\.(\\w+)$",
        ),
        newUnboundMetric(
            "answers_bogus",
            "Total number of answers that were bogus.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.answer\\.bogus$",
        ),
        newUnboundMetric(
            "answers_secure_total",
            "Total number of answers that were secure.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.answer\\.secure$",
        ),
        newUnboundMetric(
            "cache_hits_total",
            "Total number of queries that were successfully answered using a cache lookup.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.cachehits$",
        ),
        newUnboundMetric(
            "cache_misses_total",
            "Total number of cache queries that needed recursive processing.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.cachemiss$",
        ),
        newUnboundMetric(
            "memory_caches_bytes",
            "Memory in bytes in use by caches.",
            dto.MetricType_GAUGE,
            []string{"cache"},
            "^mem\\.cache\\.(\\w+)$",
        ),
        newUnboundMetric(
            "memory_modules_bytes",
            "Memory in bytes in use by modules.",
            dto.MetricType_GAUGE,
            []string{"module"},
            "^mem\\.mod\\.(\\w+)$",
        ),
        newUnboundMetric(
            "memory_sbrk_bytes",
            "Memory in bytes allocated through sbrk.",
            dto.MetricType_GAUGE,
            []string{},
            "^mem\\.total\\.sbrk$",
        ),
        newUnboundMetric(
            "prefetches_total",
            "Total number of cache prefetches performed.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.prefetch$",
        ),
        newUnboundMetric(
            "queries_total",
            "Total number of queries received.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.queries$",
        ),
        newUnboundMetric(
            "expired_total",
            "Total number of expired entries served.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.expired$",
        ),
        newUnboundMetric(
            "query_classes_total",
            "Total number of queries with a given query class.",
            dto.MetricType_COUNTER,
            []string{"class"},
            "^num\\.query\\.class\\.([\\w]+)$",
        ),
        newUnboundMetric(
            "query_flags_total",
            "Total number of queries that had a given flag set in the header.",
            dto.MetricType_COUNTER,
            []string{"flag"},
            "^num\\.query\\.flags\\.([\\w]+)$",
        ),
        newUnboundMetric(
            "query_ipv6_total",
            "Total number of queries that were made using IPv6 towards the Unbound server.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.query\\.ipv6$",
        ),
        newUnboundMetric(
            "query_opcodes_total",
            "Total number of queries with a given query opcode.",
            dto.MetricType_COUNTER,
            []string{"opcode"},
            "^num\\.query\\.opcode\\.([\\w]+)$",
        ),
        newUnboundMetric(
            "query_edns_DO_total",
            "Total number of queries that had an EDNS OPT record with the DO (DNSSEC OK) bit set present.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.query\\.edns\\.DO$",
        ),
        newUnboundMetric(
            "query_edns_present_total",
            "Total number of queries that had an EDNS OPT record present.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.query\\.edns\\.present$",
        ),
        newUnboundMetric(
            "query_tcp_total",
            "Total number of queries that were made using TCP towards the Unbound server.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.query\\.tcp$",
        ),
        newUnboundMetric(
            "query_tls_total",
            "Total number of queries that were made using TCP TLS towards the Unbound server.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.query\\.tls$",
        ),
        newUnboundMetric(
            "query_types_total",
            "Total number of queries with a given query type.",
            dto.MetricType_COUNTER,
            []string{"type"},
            "^num\\.query\\.type\\.([\\w]+)$",
        ),
        newUnboundMetric(
            "request_list_current_all",
            "Current size of the request list, including internally generated queries.",
            dto.MetricType_GAUGE,
            []string{"thread"},
            "^thread([0-9]+)\\.requestlist\\.current\\.all$",
        ),
        newUnboundMetric(
            "request_list_current_user",
            "Current size of the request list, only counting the requests from client queries.",
            dto.MetricType_GAUGE,
            []string{"thread"},
            "^thread([0-9]+)\\.requestlist\\.current\\.user$",
        ),
        newUnboundMetric(
            "request_list_exceeded_total",
            "Number of queries that were dropped because the request list was full.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread([0-9]+)\\.requestlist\\.exceeded$",
        ),
        newUnboundMetric(
            "request_list_overwritten_total",
            "Total number of requests in the request list that were overwritten by newer entries.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread([0-9]+)\\.requestlist\\.overwritten$",
        ),
        newUnboundMetric(
            "recursive_replies_total",
            "Total number of replies sent to queries that needed recursive processing.",
            dto.MetricType_COUNTER,
            []string{"thread"},
            "^thread(\\d+)\\.num\\.recursivereplies$",
        ),
        newUnboundMetric(
            "rrset_bogus_total",
            "Total number of rrsets marked bogus by the validator.",
            dto.MetricType_COUNTER,
            []string{},
            "^num\\.rrset\\.bogus$",
        ),
        newUnboundMetric(
            "time_elapsed_seconds",
            "Time since last statistics printout in seconds.",
            dto.MetricType_COUNTER,
            []string{},
            "^time\\.elapsed$",
        ),
        newUnboundMetric(
            "time_now_seconds",
            "Current time in seconds since 1970.",
            dto.MetricType_GAUGE,
            []string{},
            "^time\\.now$",
        ),
        newUnboundMetric(
            "time_up_seconds_total",
            "Uptime since server boot in seconds.",
            dto.MetricType_COUNTER,
            []string{},
            "^time\\.up$",
        ),
        newUnboundMetric(
            "unwanted_queries_total",
            "Total number of queries that were refused or dropped because they failed the access control settings.",
            dto.MetricType_COUNTER,
            []string{},
            "^unwanted\\.queries$",
        ),
        newUnboundMetric(
            "unwanted_replies_total",
            "Total number of replies that were unwanted or unsolicited.",
            dto.MetricType_COUNTER,
            []string{},
            "^unwanted\\.replies$",
        ),
        newUnboundMetric(
            "recursion_time_seconds_avg",
            "Average time it took to answer queries that needed recursive processing (does not include in-cache requests).",
            dto.MetricType_GAUGE,
            []string{},
            "^total\\.recursion\\.time\\.avg$",
        ),
        newUnboundMetric(
            "recursion_time_seconds_median",
            "The median of the time it took to answer queries that needed recursive processing.",
            dto.MetricType_GAUGE,
            []string{},
            "^total\\.recursion\\.time\\.median$",
        ),
        newUnboundMetric(
            "msg_cache_count",
            "The Number of Messages cached",
            dto.MetricType_GAUGE,
            []string{},
            "^msg\\.cache\\.count$",
        ),
        newUnboundMetric(
            "rrset_cache_count",
            "The Number of rrset cached",
            dto.MetricType_GAUGE,
            []string{},
            "^rrset\\.cache\\.count$",
        ),
    }
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {
    cmdArgs := []string{"stats_noreset"}

    if plugin.Config != "" {
        cmdArgs = append([]string{"-c", plugin.Config}, cmdArgs...)
    }

    cmd := exec.Command(plugin.Binary, cmdArgs...)

    if plugin.Sudo {
        cmdArgs = append([]string{plugin.Binary}, cmdArgs...)
        cmd = exec.Command("sudo", cmdArgs...)
    }

    var out bytes.Buffer
    cmd.Stdout = &out

    if err := cmd.Run(); err != nil {
        return sensu.CheckStateCritical, fmt.Errorf("failed to execute command: %v", err)
    }

    scanner := bufio.NewScanner(&out)

    histogramCount := uint64(0)
    histogramAvg := float64(0)
    histogramBuckets := make(map[float64]uint64)

    for scanner.Scan() {
        fields := strings.Split(scanner.Text(), "=")
        if len(fields) != 2 {
            return sensu.CheckStateCritical, fmt.Errorf("%q is not a valid key-value pair", scanner.Text())
        }

        for _, metric := range unboundMetrics {
            if matches := metric.pattern.FindStringSubmatch(fields[0]); matches != nil {
                value, err := strconv.ParseFloat(fields[1], 64)
                if err != nil {
                    return sensu.CheckStateCritical, err
                }
                labelPairs := makeLabelPairs(metric.labels, matches[1:])
                switch metric.metricFamily.Type.String() {
                case dto.MetricType_GAUGE.String():
                    metric.metricFamily.Metric = append(metric.metricFamily.Metric, &dto.Metric{
                        Label: labelPairs,
                        Gauge: &dto.Gauge{
                            Value: &value,
                        },
                    })
                case dto.MetricType_COUNTER.String():
                    metric.metricFamily.Metric = append(metric.metricFamily.Metric, &dto.Metric{
                        Label: labelPairs,
                        Counter: &dto.Counter{
                            Value: &value,
                        },
                    })
                default:
                    return sensu.CheckStateCritical, fmt.Errorf("metric type %s of %s is invalid or not supported", metric.metricFamily.Type.String(), *metric.metricFamily.Name)
                }

                break
            }
        }

        if matches := histogramMetric.pattern.FindStringSubmatch(fields[0]); matches != nil {
            upperBound, err := strconv.ParseFloat(matches[1], 64)
            if err != nil {
                return sensu.CheckStateCritical, err
            }
            value, err := strconv.ParseUint(fields[1], 10, 64)
            if err != nil {
                return sensu.CheckStateCritical, err
            }
            histogramBuckets[upperBound] = value
            histogramCount += value
        } else if fields[0] == "total.recursion.time.avg" {
            value, err := strconv.ParseFloat(fields[1], 64)
            if err != nil {
                return sensu.CheckStateCritical, err
            }
            histogramAvg = value
        }
    }

    keys := []float64{}
    for k := range histogramBuckets {
        keys = append(keys, k)
    }
    sort.Float64s(keys)
    prev := uint64(0)
    for _, i := range keys {
        histogramBuckets[i] += prev
        prev = histogramBuckets[i]
    }
    bucket := []*dto.Bucket{}
    for _, i := range keys {
        upperBound := i
        cumulativeCount := histogramBuckets[i]
        bucket = append(bucket, &dto.Bucket{
            UpperBound: &upperBound,
            CumulativeCount: &cumulativeCount,
        })
    }
    histogramSum := histogramAvg * float64(histogramCount)
    histogramMetric.metricFamily.Metric = append(histogramMetric.metricFamily.Metric, &dto.Metric{
        Histogram: &dto.Histogram{
            SampleCount: &histogramCount,
            SampleSum: &histogramSum,
            Bucket: bucket,
        },
    })

    unboundMetrics = append(unboundMetrics, histogramMetric)

    err := printMetrics(unboundMetrics)
    if err != nil {
        return sensu.CheckStateCritical, err
    }

	return sensu.CheckStateOK, nil
}

func makeLabelPairs(keys []string, values []string) []*dto.LabelPair {
    labelPairs := []*dto.LabelPair{}
    for i, key := range keys {
        labelPairs = append(labelPairs, &dto.LabelPair{Name: &key, Value: &values[i]})
    }
    return labelPairs
}

func printMetrics(metrics []*UnboundMetric) error {
    var buf bytes.Buffer
    for _, metric := range metrics {
        if len(metric.metricFamily.Metric) == 0 {
            continue
        }
        buf.Reset()
        encoder := expfmt.NewEncoder(&buf, expfmt.FmtText)
        err := encoder.Encode(metric.metricFamily)
        if err != nil {
            return err
        }

        fmt.Print(buf.String())
    }

    return nil
}
