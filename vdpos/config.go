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

package vdpos

import (
)

type Config struct {
	MaxSuperNodeNumber uint
	MaxValidatorNumber uint

	SmallBlockProduceNumber uint

	// unit: ms
	SmallBlockProduceInterval uint
	// unit: ms
	BlockProduceInterval uint
}