package Data::Password::BasicCheck;

use 5.008;
use strict;
use warnings;

our $VERSION = '0.01';

use constant MIN => 0 ;
use constant MAX => 1 ;
use constant SYM => 2 ;

sub new {
  my $class = shift ;

  die "Not an object method" if ref $class ;
  my ($minlen,$maxlen,$psym) = @_ ;

  # Avoid bothering about uninitialized values...
  no warnings ;
  return undef unless $minlen =~ /^\d$/ and $minlen >= 0 ;
  return undef unless $maxlen =~ /^\d$/ and $maxlen >= $minlen ;
  $psym = 2/3  unless $psym > 0 ;

  return bless [$minlen,$maxlen,$psym],$class ;
}

sub minlen { return $_[0]->[MIN] }
sub maxlen { return $_[0]->[MAX] }
sub psym   { return $_[0]->[SYM] }
sub _parms { return @{$_[0]}     }

sub check {
  my ($self,$username,$password,$name,$surname,$city) = @_ ;

  die "Not a class method!"
    unless ref $self and eval { $self->isa('Data::Password::BasicCheck') } ;

  my ($minlen,$maxlen,$psym) = $self->_parms ;
  my $plen                   = length $password ;
  # Check length
  {
    return "password is too short" if $plen < $minlen ;
    return "password is too long"  if $plen > $maxlen ;
  }

  # Password contains alphas, digits and non-alpha-digits
  {
    local $_ = $password ;
    return "Password must contain alphanumeric characters, digits and symbols"
      unless /[a-z]/i and /\d/ and /[^a-z0-9]/i ;
  }

  # Check unique characters
  {
    my @chars = split //,$password ;
    my %unique ;
    foreach my $char (@chars) { $unique{$char}++ } ;
    return "Not enough different symbols in password"
      unless scalar keys %unique >= sprintf "%.0f",$psym * $plen ;
  }

  # rotations of the password don't match it
  {
    foreach my $rot (_rotations($password)) {
      return "Password matches itself after some left rotation"
        if $rot eq $password ;
    }
  }

  # Check password against username, name, surname and city. All but
  # username could be composed, like "Alan Louis", or "Di Cioccio" or
  # "Los Angeles", so we have to treat each chunk separately.  But we
  # should also check for passwords like "alanlouis", or "dicioccio"
  # or "losangeles". So we must add them, too.
  {
    # Prepare password rotations; check reverse password and reverse
    # password rotations, too
    my $pclean                    = lc $password ;
    $pclean =~ s/[^a-z]//g ;
    my $rpclean = reverse $pclean ;
    my @prots = ($pclean, _rotations($pclean),
		 $rpclean,_rotations($rpclean)) ;

    # Prepare personal information to match @prots against
    ($name,$surname,$city) = map lc,($name,$surname,$city)  ;
    my @chunks = split(/\s+/,join(" ",$name,$surname,$city)) ;
    foreach ($name,$surname,$city) {
      if (/\s/) {
	s/\s// ;
	push @chunks,$_ ;
      }
    }
    push @chunks,lc $username ;

    my $idx ;
    foreach my $chunk (@chunks) {
      my $chunklen = length $chunk ;
      foreach my $rot (@prots) {
	my $cutrot = substr $rot,0,$minlen ;
	$idx = $chunklen >= $minlen?
	  index $chunk,$cutrot:
	  index $cutrot,$chunk;
	unless ($idx == -1) {
	  return "Your password matches personal information" ;
	}
      }
    }
  }

  return "password ok" ;
}

sub _rotations {
  my $string = shift ;
  my $n      = length $string ;
  my @result ;

  # note: $i < $n, since the n-th permutation is the password again 
  for (my $i = 1 ; $i < $n ; $i++) {
    $string = chop($string).$string ;
    push @result,$string ;
  }
  return @result ;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Data::Password::BasicCheck - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Data::Password::BasicCheck;
  blah blah blah

=head1 ABSTRACT

  This should be the abstract for Data::Password::BasicCheck.
  The abstract is used when making PPD (Perl Package Description) files.
  If you don't want an ABSTRACT you should also edit Makefile.PL to
  remove the ABSTRACT_FROM option.

=head1 DESCRIPTION

Stub documentation for Data::Password::BasicCheck, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Marco Marongiu, E<lt>bronto@c47.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Marco Marongiu

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
