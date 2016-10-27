#!perl

use Crypt::Sodium;
use strictures 2;
 
my $k = crypto_stream_key();

my $message = 'test';

sub encrypt
{
    my $key = shift;
    my $message = shift;
    my $n = crypto_stream_nonce();
    my $t = crypto_secretbox($message, $n, $key);
    return sprintf("%s:%s", unpack('H*', $n), unpack('H*', $t));
}

sub valid_hex
{
    my $text = shift;
    return $text && $text =~ /^[0-9A-F]+$/i && length($text)%2 == 0;
}

sub decrypt
{
    my $key = shift;
    my $ciphertext = shift;
    my ($nonce, $cipher) = split /:/, $ciphertext;
    die 'Invalid format' unless valid_hex($nonce) && valid_hex($cipher);
    return crypto_secretbox_open(pack('H*', $cipher), pack('H*', $nonce), $key);
}

my $encrypted = encrypt($k, $message);
print $encrypted, "\n";
my $d = decrypt($k, $encrypted);
print $d, "\n";
my @chars = split //, $encrypted;
if($chars[3] eq 'f') 
{
    $chars[3] = 'a';
}
else
{
    $chars[3] = 'f';
}
my $fudged = join '', @chars;
print "Trying to decrypt a fudged ciphertext\n";
use Data::Dumper;
print Dumper(decrypt($k, $fudged)), "\n";

print encrypt($k, $message), "\n";
print encrypt($k, $message), "\n";
print encrypt($k, $message), "\n";
print encrypt($k, $message), "\n";
print encrypt($k, $message), "\n";


