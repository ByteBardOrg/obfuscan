# Defanged: classic Perl decode-then-eval webshell shape.
# Decodes to: print "stub";
use MIME::Base64 qw(decode_base64);
my $blob = "cHJpbnQgInN0dWIiOw==";
eval(decode_base64($blob));
