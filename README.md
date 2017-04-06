# Insight Fansite Analytics Challenge

This is the solution to the problem set: https://github.com/InsightDataScience/fansite-analytics-challenge/.

Run as follows:
- Clone repo locally
- For unit tests, `cd insight_testsuite` `bash run_tests.sh`. Should see 4 tests passed.
- The folder `log_input` consists of three files - `log100.txt`consists of the first 100 logs; `log10k.txt`consists of the first 10,000 logs; `log.txt`, which is evaluated by default, consists of the first 100,000 logs. These can be used as tests by modifying `run.sh` or renaming the relevant test file to `log.txt`. 
- Run code using `bash run.sh` from repo directory.


The process_log.py source code contains 6 kinds of features/analytics:
- Features 1: Top 10 most active hosts/IP addresses. Output saved at `log_output/hosts.txt`.
- Feature 2: Top 10 resources that consume the most bandwidth. Output saved at `log_output/resources.txt`.
- Feature 3: Top 10 most busiest 60-minute time intervals for the website. Output saved at `log_output/hours.txt`.
- Feature 4: Security measure which creates a temporary block list based on repeated failed logins, as per problem set. Output saved at `log_output/blocked.txt`.
- Feature 5: Decreasing count of HTTP reply codes (gives us an estimate of the number of login failures). Output saved at `log_output/feat5.txt`.
- Feature 6: Quantify activity of top 10 hosts/IPs (feature 1) across the day (60-minute intervals). This gives us insight into user behavior and how the most active users spend their time on the website throughout the day. Output saved at `log_output/feat6.txt`.

Note: 
- Features 5 & 6 are not computed by default. Set `run_extra_features = True` inside main() to compute them.
- The 10,000 logs file gets execute in less than a minute, while the 100,000 logs file is executed within 3-4 minutes. Further speedup can be achieved by using parallelization (i.e. offloading different analytics/feature jobs to different cores).
