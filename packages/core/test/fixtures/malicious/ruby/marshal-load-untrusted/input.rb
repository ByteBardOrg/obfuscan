# Defanged: Marshal.load on attacker-controlled IO is RCE in Ruby.
require "open-uri"

def fetch_state(url)
  io = URI.open(url)
  Marshal.load(io)   # RCE if `url` is attacker-controlled
end
