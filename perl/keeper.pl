#!/usr/bin/env perl -w

#-- 
#-- Keeper Commander for Perl
#-- Keeper Security Inc.
#-- 

use strict;
use Curses::UI;
use LWP::UserAgent;
use HTTP::Request::Common;
use Term::ReadKey;
use JSON;
use Crypt::PBKDF2;
use Digest::SHA qw(sha256_base64);
use MIME::Base64::URLSafe;
use Crypt::Mode::CBC;
use Getopt::Long;
use Pod::Usage;

#-- ./keeper.pl --gui  

sub log {
  my $s = shift || '';
  print $s;
}

sub usage {

}

#-- command line params
my $debug = "";
my $email = "";
my $command = "";
my $gui = "";

GetOptions (debug   => \$debug, 
            'email=s'   => \$email, 
            gui     => \$gui, 
            'command=s' => \$command);

if( $debug ) { &log("DBG: ON\n"); }
if( $gui ) { &log("GUI: ON\n"); }
if( $command ) { &log("DEBUG: ON\n"); }
if( $email ) { &log("EMAIL: $email\n"); }

exit(0);

my @daten = (
    { "headline" => "Lorem Ipsum 1", "text" => "Lorem Ipsum 1" },
    { "headline" => "Lorem Ipsum 2", "text" => "Lorem Ipsum 2" },
    { "headline" => "Lorem Ipsum 3", "text" => "Lorem Ipsum 3" }
);

sub draw_ui {
    my $cui = new Curses::UI( -color_support => 1 );
    my $win = $cui->add("win", "Window", -border => 1, -y => 0, -title => "Keeper Password Manager & Digital Vault");
    my $max_height = $win->height();
    my $max_width = $win->width();
    my $lbox = $win->add("List", "Listbox", -fg => "white", -height => int($max_height / 2), -border => 1, => "Record Details" );
    my $tbox = $win->add("Textbox", "TextViewer", -fg => "white", -y => ($max_height / 2), -height => int($max_height / 2), -wrapping => 1, -border => 1, -title => "Record Details" );
    $lbox->onSelectionChange(sub {
        my $id = $lbox->get_active_id();
        $tbox->text($daten[$id]->{text});
    });
    $lbox->onChange(sub {
    my $id = $lbox->get_active_id();
        $cui->dialog("ID:" . $id);
    });
    $cui->set_binding( sub { exit(0); } , "\cC");
    my @headlines;
    push(@headlines, $_->{headline}) for @daten;
    $lbox->values(\@headlines);
    $lbox->focus();
    $cui->mainloop();
}

draw_ui();
