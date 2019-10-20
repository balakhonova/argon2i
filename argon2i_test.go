/*
argon2i - strengthen passwords with Argon2i
Copyright (C) 2019 Elena Balakhonova <balakhonova_e@riseup.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"testing"
)

func TestStrengthenPasswd(t *testing.T) {
	expected := "$argon2i$v=19$m=32768,t=3,p=4$MTIzNDU2Nzg$hwfe1WK6vnNwcMPG8t08rwiB7ObbmYoOX+0+PFXFJqQ"
	got := strengthenPasswd([]byte("123"), []byte("12345678"), 3, 32*1024, 32, 4)
	if expected != got {
		t.FailNow()
	}
}
