use Test::More qw(no_plan) ;

use strict ;

my ($username,@userinfo) =
  (qw(bronto Marco Marongiu),'San Gavino') ;
my $ok = "password ok" ;

BEGIN { use_ok('Data::Password::BasicCheck') };

# Test with limits 5-8 and psym = 2/3
{
  my $dpbc58 ;
  eval { $dpbc58 = Data::Password::BasicCheck->new(5,8) } ;
  is($@,'','Object created ok') ;

  my $good = 'c0m&c@z%' ;
  my @passwords = ('shrt',       # too short
		   'waytoolong', # too long
		   'pitbull',    # doesn't contain digits/symbols
		   '!@#$%^&',    # doesn't contain digits/alphas
		   '12345678',   # doesn't contain symbols/alphas
		   'pitbul1',    # doesn't contain symbols
		   'pitbull@',   # doesn't contain digits
		   '!@#$1234',   # doesn't contain alphas
		   'x1$$x11x',   # not enough symbols (should be at least 5)
		  ) ;
  is($ok,$dpbc58->check($username,$good,@userinfo),"$good is good") ;

  foreach (@passwords) {
    my $check = $dpbc58->check($username,$_,@userinfo) ;
    isnt($ok,$check,"$_: $check") ;
  }

}


# Now lower psym and check for repetitions
{
  my $dpbc58 ;
  eval { $dpbc58 = Data::Password::BasicCheck->new(5,8,.5) } ;
  is($@,'','Object created ok') ;

  my @passwords = (
		   't1c&t1c&',   # password matches itself after rotations
		   '$1marco',    # matches user's name
		   'nto1bro%',   # stripped rot. password matches username
		   'oc$ra1m;',   # stripped reversed password matches name
		   "comar1\$",   # stripped rot. password matches name
		   'ma0$ron',    # stripped rot. password matches surname
		   'sang@v1n',   # stripped rot. password matches city
		   '!gavian0',   # stripped rot. password and city match
		  ) ;

  foreach (@passwords) {
    my $check = $dpbc58->check($username,$_,@userinfo) ;
    isnt($ok,$check,"$_: $check") ;
  }


}

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

