// Copyright 2018 The Insight Chain
// This file is part of the inb-go library.
//
// The inb-go library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The inb-go library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the inb-go library. If not, see <http://www.gnu.org/licenses/>.

package common

import "strconv"

func IsEmpty(str string) bool {
	if len(str) > 0 {
		return false
	}
	return true
}

func IsBlank(str string) bool {
	//TODO 同样需要做不是空白字符的判断
	return IsEmpty(str)
}

func ToString(i int) string {
	return strconv.Itoa(i)
}
