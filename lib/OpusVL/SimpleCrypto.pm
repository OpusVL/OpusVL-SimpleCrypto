use strictures 2;
package OpusVL::SimpleCrypto;

use Moo;
use Crypt::Sodium;
use MIME::Base64;

our $VERSION = '0.001';

has key_string => (is => 'rw', lazy => 1, builder => '_build_key_string');
has key => (is => 'ro', lazy => 1, builder => '_build_key');

sub _build_key
{
    my $self = shift;
    die 'Must specify key or key_string' unless $self->key_string;
    return decode_base64($self->key_string);
}

sub _build_key_string
{
    my $self = shift;
    die 'Must specify key or key_string' unless $self->key;
    return encode_base64($self->key);
}

sub GenerateKey
{
    my $k = crypto_stream_key();
    return OpusVL::SimpleCrypto->new({key => $k});
}

sub encrypt
{
    my $self = shift;
    my $message = shift;
    my $n = crypto_stream_nonce();
    my $t = crypto_secretbox($message, $n, $self->key);
    return sprintf("%s:%s", encode_base64($n), encode_base64($t));
}

sub decrypt
{
    my $self = shift;
    my $ciphertext = shift;
    my ($nonce, $cipher) = split /:/, $ciphertext;
    return crypto_secretbox_open(decode_base64($cipher), decode_base64($nonce), $self->key);
}


1;

=head1 NAME

OpusVL::SimpleCrypto - Very simple encyption methods.

=head1 DESCRIPTION

Simple encrypt and decrypt methods.

    my $s = OpusVL::SimpleCrypto->GenerateKey;
    print $s->key_string, "\n";
    my $ct = $s->encrypt('Test');

    my $crypto = OpusVL::SimpleCrypto->new({ key_string => $key_string });
    my $message = $crypto->decrypt($ct);

This uses Crypt::Sodium under the hood to do simple symetric (authenticated)
encryption and decryption.

On debian derivative systems you probably need to install the libsodium-dev
package.

=head1 METHODS

=head2 GenerateKey

Create a key and return new OpusVL::SimpleCrypto initialized with it.

Use the key_string method to get the key out in a format useful for storing.

=head2 encrypt

Encrypt text.

=head2 decrypt

Decrypt text.  Note that ciphertext that has been meddled with will
not decrypt, and the function will return undef instead.

=head1 ATTRIBUTES

=head2 key_string

The key in a text friendly format.

=head2 key

The key in binary.

=cut
