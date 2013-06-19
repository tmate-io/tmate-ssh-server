#!/usr/bin/env ruby

# It's a bit hard to have the jailed process communicate with the parent.
# This is a workaround and is really gross. Please forgive me.

require 'rubygems'
require 'bundler'
require 'logger'
require 'set'

Bundler.require

StatsD.server = 'monitor:8125'
StatsD.mode = 'production'
StatsD.logger = Logger.new(STDERR)

hostname = Socket.gethostname
seen_tokens = Set.new

loop do
  sessions = {}
  new_sessions = 0
  paired = 0
  not_paired = 0


  Dir['/proc/*/cmdline'].map do |f|
    if File.open(f).read =~ /^tmate-slave \[(.+)\] \((.+)\) (.+)$/
      token = $1
      role = $2
      ip = $3

      new_sessions += 1 unless seen_tokens.include?(token)
      seen_tokens << token

      sessions[token] ||= []
      sessions[token] << ip
    end
  end

  sessions.map do |token, ips|
    if ips.uniq.count > 1
      paired += 1
    else
      not_paired += 1
    end
  end

  StatsD.increment("tmate.#{hostname}.sessions.total", new_sessions)
  StatsD.gauge("tmate.#{hostname}.sessions.paired", paired)
  StatsD.gauge("tmate.#{hostname}.sessions.not-paired", not_paired)

  sleep 10
end
