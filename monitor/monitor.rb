#!/usr/bin/env ruby

# It's a bit hard to have the jailed process communicate with the parent.
# This is a workaround and is really gross. Please forgive me.

require 'rubygems'
require 'bundler'
Bundler.require

require 'logger'

StatsD.server = 'monitor:8125'
StatsD.logger = Logger.new(STDERR)
StatsD.mode = 'production'

hostname = Socket.gethostname

loop do
  server_count = 0
  client_count = 0
  ips = []

  Dir['/proc/*/cmdline'].map do |f|
    if File.open(f).read =~ /^tmate-slave \[(.+)\] \((.+)\) (.+)$/
      token = $1
      role = $2
      ip = $3

      server_count += 1 if role == 'server'
      client_count += 1 if role == 'client'
      ips << ip
    end
  end

  StatsD.gauge("tmate.#{hostname}.servers", server_count)
  StatsD.gauge("tmate.#{hostname}.clients", client_count)
  StatsD.gauge("tmate.#{hostname}.unique_ips", ips.uniq.count)

  sleep 10
end
