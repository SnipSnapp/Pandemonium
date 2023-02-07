use String::Random;
use File::Slurper 'read_text';
use Cwd qw();
my $path = Cwd::cwd();
print "$path\n";
my $content = read_text('.\Snort\pcre_gen.txt');
open(FH, '>','.\Snort\pcre_gen.txt');
print $content;
my $string_gen = String::Random->new;

print FH $string_gen->randregex($content);;
close(FH);
