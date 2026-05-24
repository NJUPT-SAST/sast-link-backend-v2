package domain

type Organize struct {
	ID  int16  `gorm:"column:id;type:smallint;primaryKey"`
	Dep string `gorm:"column:dep;type:varchar(64);not null"`
	Org string `gorm:"column:org;type:varchar(64);default:null"`
}

// TableName overrides the default table name.
func (Organize) TableName() string {
	return "organize"
}
