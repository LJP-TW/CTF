#!/usr/bin/ruby
require 'json'

STDOUT.sync = true

puts "Your name:"
name = STDIN.gets.chomp
puts "Your age:"
age = STDIN.gets.chomp

if age.match(/[[:alpha:]]/)
    puts "No!No!No!"
    exit
end


string = "{\"name\":\"#{name}\",\"is_admin\":\"no\", \"age\":\"#{age}\"}"
res = JSON.parse(string)

if res['is_admin'] == "yes"
    puts "AIS3{xxxxxxxxxxxx}"  # flag is here
else
    puts "Hello, " + res['name']
    puts res
end
