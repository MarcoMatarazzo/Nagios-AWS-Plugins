#!/usr/bin/ruby

# Based on SecludIT gem secludit-nagios

require 'getoptlong'
require 'rubygems'
require 'fog'
require 'pp'
require 'base64'
require 'openssl'
require 'yaml'

# sudo apt-get install ruby-dev libxml2-dev build-essential libcurl4-openssl-dev

#puts AWS::Cloudwatch::API_VERSION

# define static values
EC2_STATUS_CODE_PENDING = 0
EC2_STATUS_CODE_RUNNING = 16
EC2_STATUS_CODE_TERMINATING = 32
EC2_STATUS_CODE_STOPPING = 64
EC2_STATUS_CODE_STOPPED = 80

EC2_STATUS_NAME_PENDING	= "pending"
EC2_STATUS_NAME_RUNNING	= "running"
EC2_STATUS_NAME_TERMINATING = "terminating"
EC2_STATUS_NAME_STOPPING = "stopping"
EC2_STATUS_NAME_STOPPED = "stopped"

EC2_STATE_ENABLED = "enabled"
EC2_STATE_PENDING = "pending"
EC2_STATE_DISABLING = "disabling"

AWS_NAMESPACE_EC2 = "AWS/EC2"
AWS_NAMESPACE_EBS = "AWS/EBS"
AWS_NAMESPACE_ELB = "AWS/ELB"
AWS_NAMESPACE_RDS = "AWS/RDS"
AWS_NAMESPACE_ELASTICACHE = "AWS/ElastiCache"

EC2_METRIC_TYPE = "ec2-metric"
EBS_METRIC_TYPE = "ebs-metric"
ELB_METRIC_TYPE = "elb-metric"
RDS_METRIC_TYPE = "rds-metric"
ELASTICACHE_METRIC_TYPE = "elasticache-metric"

NAGIOS_CODE_OK = 0		# UP
NAGIOS_CODE_WARNING = 1		# UP or DOWN/UNREACHABLE*
NAGIOS_CODE_CRITICAL = 2	# DOWN/UNREACHABLE
NAGIOS_CODE_UNKNOWN = 3		# DOWN/UNREACHABLE
NAGIOS_OUTPUT_SEPARATOR = "|"

CLOUDWATCH_TIMER = 600
CLOUDWATCH_DETAILED_TIMER = 180
CLOUDWATCH_PERIODE = 120

# specify the options we accept and initialize and the option parser
verbose = 0
instance_id = ''
access_key_id = ''
secret_access_key = ''
ec2_endpoint = ''
rds_endpoint = ''
elb_endpoint = ''
elasticache_endpoint = ''
cloudwatch_endpoint = ''
region = ''
address = ''
metric = ''
metric_type = ''
stat = 'Average,Maximum,Minimum'
ret = NAGIOS_CODE_UNKNOWN 
warning_values = []
critical_values = []
credential_file = ''
cloudwatch_timer = CLOUDWATCH_TIMER
cloudwatch_period = CLOUDWATCH_PERIODE
use_rsa = false
namespace = AWS_NAMESPACE_EC2
dimensions = nil
available = ''


  def display_menu
    puts "Usage: #{$0} [-v] -a <address> -i <instance_id> -f <credentials>"
    puts "  --help, -h:               This Help"
    puts "  --verbose, -v:            Enable verbose mode"
    puts "  --address, -a:            Amazon Object (Instance, Database, LoadBalancer, Cluster) Address or Region"
    puts "  --instance_id, -i:        Amazon Object ID (Instance, Database, LoadBalancer, Cluster) Identifier"
    puts "  --credential_file, -f:    Path to a File containing the Amazon EC2 Credentials"
    puts "  --ec2-metric, -C:         One of Amazon EC2 Metrics"
    puts "                            (CPUUtilization, NetworkIn, NetworkOut, DiskWriteOps, DiskReadBytes, DiskReadOps, DiskWriteBytes, ...)"
    puts "  --elb-metric, -L:         One fo Amazon Load Balancing Metrics"
    puts "                            (Latency, RequestCount, HealthyHostCount, UnHealthyHostCount, ...)"
    puts "  --rds-metric, -D:         One of Amazon RDS Metrics"
    puts "                            (CPUUtilization, FreeStorageSpace, DatabaseConnections, ReadIOPS, WriteIOPS, ReadLatency, WriteLatency,"
    puts "                            ReadThroughput, WriteThroughput, ...)"
    puts "  --elasticache-metric, -M: One of Amazon ElastiCache Metrics"
    puts "                            (CPUUtilization, FreeableMemory, NetworkBytesIn, NetworkBytesOut, SwapUsage)"
    puts "  --stat, -S:               Amazon Statistic used for threshold and ranges (Average, Sum, SampleCount, Maximum, Minimum)"
    exit NAGIOS_CODE_UNKNOWN
  end

  def set_threshold( arg_str )
    arg = String.new( arg_str )
    values = []
    if (arg =~ /^[0-9]+$/)
      values[0] = 0
      values[1] = arg.to_f()
    elsif (arg =~ /^[0-9]+:$/)
      values[0] = arg.gsub!( /:/, '' ).to_f()
      values[1] = (+1.0/0.0)	# +Infinity
    elsif (arg =~ /^~:[0-9]+$/)
      arg.gsub!( /~/, '' )
      values[0] = (-1.0/0.0)	# -Infinity
      values[1] = arg.gsub!( /:/, '' ).to_f()
    elsif (arg =~ /^[0-9]+:[0-9]+$/)
      values_str = arg.split( /:/ )
      values[0] = values_str[0].to_f()
      values[1] = values_str[1].to_f()
    elsif (arg =~ /^@[0-9]+:[0-9]+$/)
      arg.gsub!( /@/, '' )
      values_str = arg.split( /:/ )
      values_str.reverse!()
      values[0] = values_str[0].to_f()
      values[1] = values_str[1].to_f()
    end
    return values
  end

  def check_threshold( arg_str, warn_values, crit_values )
    arg_num = arg_str.to_f()
    if ((crit_values[0]).to_f() < (crit_values[1]).to_f()) &&
      (arg_num < (crit_values[0]).to_f() || arg_num > (crit_values[1]).to_f())
      return NAGIOS_CODE_CRITICAL
    elsif ((crit_values[0]).to_f() > (crit_values[1]).to_f()) &&
      (arg_num < (crit_values[0]).to_f() && arg_num > (crit_values[1]).to_f())
      return NAGIOS_CODE_CRITICAL
    end

    if ((warn_values[0]).to_f() < (warn_values[1]).to_f()) && 
      (arg_num < (warn_values[0]).to_f() || arg_num > (warn_values[1]).to_f())
      return NAGIOS_CODE_WARNING
    elsif ((warn_values[0]).to_f() > (warn_values[1]).to_f()) &&
      (arg_num < (warn_values[0]).to_f() && arg_num > (warn_values[1]).to_f())
      return NAGIOS_CODE_WARNING
    end

    return NAGIOS_CODE_OK
  end


opts = GetoptLong.new


# add options
opts.set_options(
        [ "--help", "-h", GetoptLong::OPTIONAL_ARGUMENT ], \
        [ "--verbose", "-v", GetoptLong::OPTIONAL_ARGUMENT ], \
        [ "--address", "-a", GetoptLong::OPTIONAL_ARGUMENT ], \
        [ "--instance_id", "-i", GetoptLong::OPTIONAL_ARGUMENT ], \
        [ "--credential_file", "-f", GetoptLong::OPTIONAL_ARGUMENT ], \
	      [ "--ec2-metric", "-C", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--elb-metric", "-L", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--rds-metric", "-D", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--elasticache-metric", "-M", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--stat", "-S", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--warning", "-w", GetoptLong::OPTIONAL_ARGUMENT], \
	      [ "--critical", "-c", GetoptLong::OPTIONAL_ARGUMENT] )

# test usage
unless ARGV.length >= 5
  display_menu
end


# parse options
opts.each { |opt, arg|
  case opt
    when '--help'
      display_menu
    when '--verbose'
      verbose = 1
    when '--address'
      address = arg
      # TODO default: us-east-1
      ec2_endpoint = "ec2.#{address}.amazonaws.com"
      rds_endpoint = "rds.#{address}.amazonaws.com"
      elb_endpoint = "elasticloadbalancing.#{address}.amazonaws.com"
      elasticache_endpoint = "elasticache.#{address}.amazonaws.com"
      cloudwatch_endpoint = "monitoring.#{address}.amazonaws.com"
      region = "#{address}"
    when '--instance_id'
      instance_id = arg
    when '--credential_file'
      credential_file = arg
    when '--ec2-metric'
      metric = arg
      metric_type = EC2_METRIC_TYPE
      namespace = AWS_NAMESPACE_EC2
    when '--elb-metric'
      metric = arg
      metric_type = ELB_METRIC_TYPE
      namespace = AWS_NAMESPACE_ELB
    when '--rds-metric'
      metric = arg
      metric_type = RDS_METRIC_TYPE
      namespace = AWS_NAMESPACE_RDS
    when '--elasticache-metric'
      metric = arg
      metric_type = ELASTICACHE_METRIC_TYPE
      namespace = AWS_NAMESPACE_ELASTICACHE
    when '--stat'
      stat = arg
    # threshold and ranges
    when '--warning'
      warning_values = set_threshold( arg )
    when '--critical'
      critical_values = set_threshold( arg )
  end
}


if (metric.empty? || cloudwatch_endpoint.empty? || address.empty?)
    display_menu
end

if namespace.eql?(AWS_NAMESPACE_EC2)
  dimensions = [{"Name" => "InstanceId", "Value" => instance_id}] # where instance_id == viid
elsif namespace.eql?(AWS_NAMESPACE_RDS)
  dimensions = [{"Name" => "DBInstanceIdentifier", "Value" => instance_id}] # where instance_id = db name
elsif namespace.eql?(AWS_NAMESPACE_ELB)
  dimensions = [{"Name" => "LoadBalancerName", "Value" => instance_id }] # where instance_id = elb name
elsif namespace.eql?(AWS_NAMESPACE_ELASTICACHE)
  dimensions = [{"Name" => "CacheClusterId", "Value" => instance_id }] # where instance_id = cluster id
end

begin
  ### TODO: re-add symmetric encryption using ED25519 key later
  conf = YAML.load_file(credential_file)
  access_key_id = conf.ec2_access_key
  secret_access_key = conf.ec2_secret 
rescue Exception => e
  puts "Error occured while retrieving and decrypting credentials for instance #{instance_id} on Amazon Server: #{address}: #{e}"
  exit NAGIOS_CODE_CRITICAL
end


if verbose == 1
  puts "** Launching AWS status retrieval on instance ID: #{instance_id}"
  puts "Amazon AWS Endpoint: EC2 #{ec2_endpoint}, RDS #{rds_endpoint}, ELB #{elb_endpoint}, ElastiCache #{elasticache_endpoint}"
  puts "Amazon CloudWatch Endpoint: #{cloudwatch_endpoint}"
  puts "Warning values: #{warning_values.inspect}"
  puts "Critical values: #{critical_values.inspect}"
end

#
# Real job
begin
  if namespace.eql?(AWS_NAMESPACE_EC2)
    aws_api = Fog::Compute.new(:provider => "aws", :aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key, :region => region)
  elsif namespace.eql?(AWS_NAMESPACE_RDS)
    aws_api = Fog::AWS::RDS.new(:aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key, :region => region)
  elsif namespace.eql?(AWS_NAMESPACE_ELB)
    aws_api = Fog::AWS::ELB.new(:aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key, :region => region)
  elsif namespace.eql?(AWS_NAMESPACE_ELASTICACHE)
    aws_api = Fog::AWS::Elasticache.new(:aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key, :region => region)
  end
rescue Exception => e
  puts "Error occured while trying to connect to AWS Endpoint: #{e}"
  exit NAGIOS_CODE_CRITICAL
end


cloudwatch_enabled = nil

begin
  if namespace.eql?(AWS_NAMESPACE_EC2)
    #EC2 
    instance = aws_api.describe_instances("instance-id" => instance_id).data[:body]
    ec2_instance_nb = instance['reservationSet'].length
    # Check whether we get the correct instance
    if (ec2_instance_nb == 0)
      puts "Error occured while retrieving EC2 instance: No instance found for instance ID #{instance_id}"
      #exit NAGIOS_CODE_CRITICAL
    elsif (ec2_instance_nb > 1)
      puts "Error occured while retrieving EC2 instance: More than one instance found for instance ID #{instance_id}"
      #exit NAGIOS_CODE_CRITICAL
    end
    state_name = instance['reservationSet'][0]['instancesSet'][0]['instanceState']['name']
    state_code = instance['reservationSet'][0]['instancesSet'][0]['instanceState']['code']
    # Check if Cloudwatch monitoring is enabled
    cloudwatch_enabled = instance['reservationSet'][0]['instancesSet'][0]['monitoring']['state'] ## true or false
  elsif namespace.eql?(AWS_NAMESPACE_RDS)
    #RDS
    instance = aws_api.describe_db_instances(instance_id).data[:body]
    if instance['DescribeDBInstancesResult']['DBInstances'].nil? || instance['DescribeDBInstancesResult']['DBInstances'].empty?
      puts "Error occured while retrieving RDS instance: no instance found for ID #{instance_id}" 
    else
      status = instance['DescribeDBInstancesResult']['DBInstances'][0]['DBInstanceStatus']
      available = instance['DescribeDBInstancesResult']['DBInstances'][0]['AllocatedStorage'].to_f * 1024 * 1024 * 1024
      if status.eql?("available")
        state_name = EC2_STATUS_NAME_RUNNING
      end
      cloudwatch_enabled = EC2_STATE_ENABLED ## available
    end
  elsif namespace.eql?(AWS_NAMESPACE_ELB)
    #ELB
    instance = aws_api.describe_load_balancers(instance_id).data[:body]
    if instance['DescribeLoadBalancersResult']['LoadBalancerDescriptions'].nil? || instance['DescribeLoadBalancersResult']['LoadBalancerDescriptions'].empty?
      puts "Error occured while retrieving ELB: no ELB found for ID #{instance_id}"
      #exit NAGIOS_CODE_CRITICAL
    else
      instances = instance['DescribeLoadBalancersResult']['LoadBalancerDescriptions'][0]['Instances']
      if !instances.nil? && !instances.empty?
        state_name = EC2_STATUS_NAME_RUNNING
      end
      #cloudwatch_enabled = EC2_STATE_ENABLED
      cloudwatch_enabled = EC2_STATE_DISABLING ## disabling
    end
  elsif namespace.eql?(AWS_NAMESPACE_ELASTICACHE)
    #ElasticCache
    instance = aws_api.describe_cache_clusters(instance_id).data[:body]
    if instance['CacheClusters'].nil? || instance['CacheClusters'].empty?
      puts "Error occured while retrieving ElastiCache cluster: no cluster found for ID #{instance_id}"
    else
      status = instance['CacheClusters'][0]['CacheClusterStatus']
      if status.eql?("available")
        state_name = EC2_STATUS_NAME_RUNNING
      end
      cloudwatch_enabled = EC2_STATE_DISABLING ## disabling
    end
  end
rescue Exception => e
  puts "Error occured while trying to retrieve AWS instance: #{e}"
  exit NAGIOS_CODE_CRITICAL
end

# interesting debug
if verbose == 1
  if namespace.eql?(AWS_NAMESPACE_EC2)
    puts "AWS EC2 Instance:"
  elsif namespace.eql?(AWS_NAMESPACE_RDS)
    puts "AWS RDS Instance:"
  elsif namespace.eql?(AWS_NAMESPACE_ELB)
    puts "AWS ELB:"
  elsif namespace.eql?(AWS_NAMESPACE_ELASTICACHE)
    puts "AWS ElastiCache Cluster:"
  end
  pp instance
end

case state_name
  when EC2_STATUS_NAME_PENDING
    ret = NAGIOS_CODE_WARNING
    nagios_state_name = "WARNING"
  when EC2_STATUS_NAME_RUNNING
    ret = NAGIOS_CODE_OK
    nagios_state_name = "OK"
  when EC2_STATUS_NAME_STOPPING
    ret = NAGIOS_CODE_WARNING
    nagios_state_name = "WARNING"
  when EC2_STATUS_NAME_STOPPED
    ret = NAGIOS_CODE_CRITICAL
    nagios_state_name = "CRITICAL"
end

if ret != NAGIOS_CODE_OK
  puts "Instance #{instance_id} is not running, so real-time monitoring is not available"
  exit ret
elsif !(cloudwatch_enabled.nil?) && (cloudwatch_enabled == EC2_STATE_ENABLED)
  if verbose == 1
    puts "CloudWatch Detailed Monitoring is enabled for Instance #{instance_id}"
  end
  cloudwatch_timer = CLOUDWATCH_DETAILED_TIMER
end

####
#  CloudWatch

begin
  cloudwatch = Fog::AWS::CloudWatch.new( :aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key, :region => region )
rescue Exception => e
  puts "Error occured while trying to connect to CloudWatch server: #{e}"
  exit NAGIOS_CODE_CRITICAL
end

# interesting debug
if verbose == 1
  puts "CloudWatch:"
  pp cloudwatch
end

begin
  #statistics = "Average,Minimum,Maximum,Sum,SampleCount"
  statistics = stat.split(",")
  time = Time.now()
  cloudwatch_metrics_stats = cloudwatch.get_metric_statistics( #:measure_name => "#{metric}",
                                                               "Namespace" => namespace,
                                                               "MetricName" => metric, 
                                                               "StartTime" => (time - cloudwatch_timer).iso8601,
                                                               "EndTime" => time.iso8601,
                                                               "Period" => cloudwatch_period,
                                                               "Statistics" => statistics,
                                                               #:custom_unit => 'Percent',
                                                               "Dimensions" => dimensions ).data[:body]
rescue Exception => e
  puts "Error occured while trying to retrieve CloudWatch metrics statistics: #{e}"
  exit NAGIOS_CODE_CRITICAL
end

# interesting debug
if verbose == 1
  puts "CloudWatch Metrics Statistics:"
  pp cloudwatch_metrics_stats
end

average = "NaN"
maximum = "NaN"
minimum = "NaN"
sum = "NaN"
sample_count = "NaN"
cloudwatch_svc_output = "CloudWatch Metric: #{metric}"
cloudwatch_svc_perfdata = ""
if (cloudwatch_metrics_stats.nil? || cloudwatch_metrics_stats.empty?)
  ret = NAGIOS_CODE_WARNING
elsif cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"].nil? || cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"].empty?
  cloudwatch_svc_output += ": No AWS CloudWatch Datapoint retrieved"
  ret = NAGIOS_CODE_WARNING
elsif !(cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"].nil? || cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"].empty?)
  if /Average/i =~ stat
    average = sprintf( "%.2f", cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"][0]["Average"] )
    cloudwatch_svc_output += ", Average: #{average}"
    cloudwatch_svc_perfdata += "metric_average=#{average} "
  end
  if /Maximum/i =~ stat
    maximum = sprintf( "%.2f", cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"][0]['Maximum'] )
    cloudwatch_svc_output += ", Maximum: #{maximum}"
    cloudwatch_svc_perfdata += "metric_maximum=#{maximum} "
  end
  if /Minimum/i =~ stat
    minimum = sprintf( "%.2f", cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"][0]['Minimum'] )
    cloudwatch_svc_output += ", Minimum: #{minimum}"
    cloudwatch_svc_perfdata += "metric_minimum=#{minimum} "
  end
  if /Sum/i =~ stat
    sum = sprintf( "%.2f", cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"][0]['Sum'] )
    cloudwatch_svc_output += ", Sum: #{sum}"
    cloudwatch_svc_perfdata += "metric_sum=#{sum} "
  end
  if /SampleCount/i =~ stat
    sample_count = sprintf( "%.2f", cloudwatch_metrics_stats["GetMetricStatisticsResult"]["Datapoints"][0]['SampleCount'] )
    cloudwatch_svc_output += ", SampleClount: #{sample_count}"
    cloudwatch_svc_perfdata += "metric_sample_count=#{sample_count} "
  end
  ret = NAGIOS_CODE_OK
  # check for threshold and ranges
  case stat
    when 'Average'
      ret = check_threshold( average, warning_values, critical_values )
    when 'Sum'
      ret = check_threshold( sum, warning_values, critical_values )
    when 'SampleCount'
      ret = check_threshold( sample_count, warning_values, critical_values )
    when 'Maximum'
      ret = check_threshold( maximum, warning_values, critical_values )
    when 'Minimum'
      ret = check_threshold( minimum, warning_values, critical_values )
    else
      ret = check_threshold( average, warning_values, critical_values )
  end
else
  ret = NAGIOS_CODE_UNKNOWN
end

# print SERVICEOUTPUT
#service_output = "CloudWatch Metric: #{metric}, Average: #{average}, Maximum: #{maximum}, Minimum: #{minimum}, Sum: #{sum}"
service_output = cloudwatch_svc_output

# print SERVICEPERFDATA
#service_perfdata = "metric_average=#{average} metric_maximum=#{maximum} metric_minimum=#{minimum} metric_sum=#{sum}"
service_perfdata = cloudwatch_svc_perfdata.rstrip!

# output
puts "#{service_output}|#{service_perfdata}"

exit ret
