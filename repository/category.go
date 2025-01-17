package repository

import (
	"a21hc3NpZ25tZW50/model"

	"gorm.io/gorm"
)

type CategoryRepository interface {
	Store(Category *model.Category) error
	Update(id int, category model.Category) error
	Delete(id int) error
	GetByID(id int) (*model.Category, error)
	GetList() ([]model.Category, error)
}

type categoryRepository struct {
	db *gorm.DB
}

func NewCategoryRepo(db *gorm.DB) *categoryRepository {
	return &categoryRepository{db}
}

func (c *categoryRepository) Store(Category *model.Category) error {
	err := c.db.Create(Category).Error
	if err != nil {
		return err
	}

	return nil
}

func (c *categoryRepository) Update(id int, category model.Category) error {
	result := c.db.Model(&model.Category{}).Where("id = ?", id).Updates(category)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (c *categoryRepository) Delete(id int) error {
	result := c.db.Delete(&model.Category{}, id)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (c *categoryRepository) GetByID(id int) (*model.Category, error) {
	var category model.Category
	err := c.db.First(&category, id).Error
	if err != nil {
		return nil, err
	}

	return &category, nil
}

func (c *categoryRepository) GetList() ([]model.Category, error) {
	var categories []model.Category
	result := c.db.Find(&categories)
	if result.Error != nil {
		return nil, result.Error
	}
	return categories, nil
}
