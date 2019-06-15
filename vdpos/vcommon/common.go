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

package vcommon

import (
	"errors"
	"math/rand"
)

//func CurrentNode() *node.Node  {
//	return node.CurrentNode
//}

func Random(strings []string, length int) (string, error) {
	if len(strings) <= 0 {
		return "", errors.New("the length of the parameter strings should not be less than 0")
	}

	if length <= 0 || len(strings) <= length {
		return "", errors.New("the size of the parameter length illegal")
	}

	for i := len(strings) - 1; i > 0; i-- {
		num := rand.Intn(i + 1)
		strings[i], strings[num] = strings[num], strings[i]
	}

	str := ""
	for i := 0; i < length; i++ {
		str += strings[i]
	}
	return str, nil
}

func RandomInt(ints []int) {
	if len(ints) <= 0 {
		return
	}

	for i := len(ints) - 1; i > 0; i-- {
		num := rand.Intn(i + 1)
		ints[i], ints[num] = ints[num], ints[i]
	}
}
