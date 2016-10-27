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

    my $s = OpusVL::SimpleCrypto->GenerateKey;
    print $s->key_string, "\n";
    my $ct = $s->encrypt('Test');

    my $crypto = OpusVL::SimpleCrypto->new({ key_string => $key_string });
    my $message = $crypto->decrypt($ct);



=head1 METHODS

=head2 GenerateKey

=head2 encrypt

=head2 decrypt

=head1 ATTRIBUTES

=head2 key_string

=head2 key


=cut
