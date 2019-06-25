require 'json'

tester = "123\",\"is_admin\":\"yes"

tester2 = "\x35"

if tester2.match(/[[:alpha:]]/)
    puts "No"
    exit
end

string = "{\"is_admin\":\"no\", \"tester\":\"#{tester}\"}"
res = JSON.parse(string)

puts res['is_admin']
puts res

string2 = "{\"tester2\":\"#{tester2}\"}"
puts string2
