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
seen_not_paired_tokens = Set.new
seen_paired_tokens = Set.new

loop do
  sessions = {}
  new_not_paired_sessions = 0
  new_paired_sessions = 0
  paired = 0
  not_paired = 0


  Dir['/proc/*/cmdline'].map do |f|
    if File.read(f) =~ /^tmate-ssh-server \[(.+)\] \((.+)\) (.+)$/
      token = $1
      role = $2
      ip = $3

      sessions[token] ||= []
      sessions[token] << ip
    end
  end

  sessions.map do |token, ips|
    if ips.uniq.count > 1
      new_not_paired_sessions += 1 unless seen_not_paired_tokens.include?(token)
      seen_not_paired_tokens << token
      new_paired_sessions += 1 unless seen_paired_tokens.include?(token)
      seen_paired_tokens << token

      paired += 1
    else
      new_not_paired_sessions += 1 unless seen_not_paired_tokens.include?(token)
      seen_not_paired_tokens << token

      not_paired += 1
    end
  end

  StatsD.increment("tmate.#{hostname}.sessions.not-paired.total", new_not_paired_sessions)
  StatsD.increment("tmate.#{hostname}.sessions.paired.total", new_paired_sessions)
  StatsD.gauge("tmate.#{hostname}.sessions.paired", paired)
  StatsD.gauge("tmate.#{hostname}.sessions.not-paired", not_paired)

  sleep 10
end
