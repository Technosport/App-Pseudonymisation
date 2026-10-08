package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// printBanner affiche le logo officiel Technosport AMU et l'état du serveur dans la console.
func printBanner(version, url string) {
	noColor := os.Getenv("NO_COLOR") != ""

	esc := func(code string) string {
		if noColor {
			return ""
		}
		return code
	}

	rst    := esc("\033[0m")
	bold   := esc("\033[1m")
	div    := esc("\033[38;2;90;100;115m")
	sub    := esc("\033[38;2;180;185;195m")
	logo   := esc("\033[1;38;2;255;255;255m")

	// Cadre de statut
	border := esc("\033[38;2;70;80;95m")
	lbl    := esc("\033[38;2;150;155;170m")
	val    := esc("\033[38;2;240;242;248m")
	urlCol := esc("\033[1;38;2;56;189;248m")
	green  := esc("\033[38;2;52;211;153m")
	amber  := esc("\033[38;2;251;191;36m")

	fmt.Println()
	// Logo officiel vectoriel amU | TECHNOSPORT reproduit fidèlement
	fmt.Printf("  %s                 ⣿⡇   ⣿%s            %s│%s ⢸⡟⠛⠛⠒⣆      ⣀⣀                        ⡴⠶%s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s   ⢀⣀⡀  ⣀ ⣀⡀ ⢀⣀  ⣿⡇   ⣿%s            %s│%s ⠘⢃⣀⣀⣀⣟⣀⡀ ⢀⣀ ⣇⣹⣇⡀⢀           ⣀⣀⣀⢀⣤⠤⡄⡴⠶⠺⠃ %s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s  ⣰⡿⠿⣿⡄ ⣿⡾⠿⣿⣴⠿⢿⣧ ⣿⡇   ⣿ %sAix        %s│%s  ⠛⢻⣿⠛⢃⣀⡉ ⢉⣉⡃⢹⣇⣀⡉⢋⣉⣉⠳ ⣀⣀ ⢚⣋⡛⢘⣉⣁⡉ ⢀⣀⡀⢀⣀⣀⣸⣇%s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s  ⠻⠃⢀⣸⡇ ⣿⠁ ⢹⡏ ⠘⣿ ⣿⡇   ⣿ %sMarseille  %s│%s   ⢸⣿⢠⣿⣉⣿⣤⣿⠙⠿⢸⡟⢹⣧⢸⡟⢹⡇⣼⡏⢹⣇⢿⣍⡛⢸⣿⠙⣿⣰⡿⠙⣿⢸⣿⠛⢻⡟%s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s  ⣰⣾⠿⢻⡇ ⣿  ⢸⡇  ⣿ ⣿⡇   ⣿ %sUniversité %s│%s   ⢸⣿⠘⣿⣉⣿⠹⣿⣠⣶⢸⡇⢸⣿⢸⡇⢸⡇⢿⣇⣸⡏⣼⣉⣿⢸⣿⣀⣿⠹⣷⣠⣿⢸⣿ ⢸⣧%s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s  ⣿⠁ ⣸⡇ ⣿  ⢸⡇  ⣿ ⢿⣇  ⣰⣿%s            %s│%s   ⠈⠉ ⠈⠉⠁ ⡈⠉⣁⣈⣁⣌⣩⣬⡥⠾⠷ ⠉⠉⠐⢮⣍⣭⣼⣿⣉⣁⢀⡉⠉⡁⠈⠉  ⠉%s\n",
		logo, sub, div, logo, rst)
	fmt.Printf("  %s  ⢻⣷⣾⠿⣿⠄⣿  ⢸⡇  ⣿ ⠘⢿⣷⣾⡿⠃%s            %s│%s   ⠦⠴⠆⠙⠲⠚⠁⠉⠋⠁⠉⠉             ⢯⣭⡏⠁ ⠙⠛⠁⠛⠛⠃⠘⠶%s\n",
		logo, sub, div, logo, rst)
	fmt.Println()

	// Panneau d'informations
	const innerWidth = 74
	bar := strings.Repeat("─", innerWidth)

	pad := func(visibleRunes int) string {
		n := innerWidth - visibleRunes
		if n < 0 {
			return ""
		}
		return strings.Repeat(" ", n)
	}

	titleRunes := utf8.RuneCountInString("  Technosport AMU · Module de Pseudonymisation")
	vRunes := utf8.RuneCountInString(version)
	line1Spaces := pad(titleRunes + 1 + vRunes)

	urlPrompt := "  ● Serveur local :   "
	urlSpaces := pad(utf8.RuneCountInString(urlPrompt) + utf8.RuneCountInString(url))

	navText := "  ✔ Interface Web ouverte automatiquement dans votre navigateur"
	navSpaces := pad(utf8.RuneCountInString(navText))

	impText := "  ▲ Important :       Ne fermez pas cette console d'exécution."
	impSpaces := pad(utf8.RuneCountInString(impText))

	quitText := "  ✕ Pour quitter :    Bouton « Quitter » dans l'interface ou [Ctrl+C]"
	quitSpaces := pad(utf8.RuneCountInString(quitText))

	blank := strings.Repeat(" ", innerWidth)

	fmt.Printf("  %s╭%s╮%s\n", border, bar, rst)
	fmt.Printf("  %s│%s  %sTechnosport AMU%s %s· Module de Pseudonymisation%s%s%s%s%s %s│%s\n",
		border, rst, bold, rst, lbl, rst, line1Spaces, val, version, rst, border, rst)
	fmt.Printf("  %s├%s┤%s\n", border, bar, rst)
	fmt.Printf("  %s│%s%s%s│%s\n", border, rst, blank, border, rst)
	fmt.Printf("  %s│%s  %s●%s %sServeur local :%s   %s%s%s%s%s│%s\n",
		border, rst, green, rst, lbl, rst, urlCol, url, rst, urlSpaces, border, rst)
	fmt.Printf("  %s│%s  %s✔%s %sInterface Web ouverte automatiquement dans votre navigateur%s%s%s│%s\n",
		border, rst, green, rst, val, rst, navSpaces, border, rst)
	fmt.Printf("  %s│%s%s%s│%s\n", border, rst, blank, border, rst)
	fmt.Printf("  %s│%s  %s▲%s %sImportant :%s       %sNe fermez pas cette console d'exécution.%s%s%s│%s\n",
		border, rst, amber, rst, lbl, rst, val, rst, impSpaces, border, rst)
	fmt.Printf("  %s│%s  %s✕%s %sPour quitter :%s    Bouton %s« Quitter »%s dans l'interface ou %s[Ctrl+C]%s%s%s│%s\n",
		border, rst, amber, rst, lbl, rst, val, rst, val, rst, quitSpaces, border, rst)
	fmt.Printf("  %s│%s%s%s│%s\n", border, rst, blank, border, rst)
	fmt.Printf("  %s╰%s╯%s\n\n", border, bar, rst)
}
