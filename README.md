# Insight Fansite Analytics Challenge

This is the solution to the problem set: https://github.com/InsightDataScience/fansite-analytics-challenge/.

Run as follows:
- Clone repo locally
- For unit tests, `cd insight_testsuite` `bash run_tests.sh`. Should see 4 tests passed.
- The folder `log_input` consists of the first 10000 logs. This can be used as a test, or the files replaced with the originals.
- Run code using `bash run.sh` from repo directory.


The process_log.py source code contains 4 kinds of features/analytics:
- Features 1: Top 10 most active hosts/IP addresses. Output saved at `log_output/hosts.txt`.
- Feature 2: Top 10 resources that consume the most bandwidth. Output saved at `log_output/resources.txt`.
- Feature 3: Top 10 most busiest 60-minute time intervals for the website. Output saved at `log_output/hours.txt`.
- Feature 4: Security measure which creates a temporary block list based on repeated failed logins, as per problem set. Output saved at `log_output/blocked.txt`.
