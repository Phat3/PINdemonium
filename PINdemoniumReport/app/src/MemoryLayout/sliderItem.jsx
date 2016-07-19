import React from 'react';


class SliderItem extends React.Component {

  constructor(){
    super()
    this.handleClick = this.handleClick.bind(this)
  }


  handleClick(event) {
    event.preventDefault()
    this.props.onSelect(this.props.id, this.props.startDump, this.props.endDump)
  }

  render () {


    var listyle = {
        background : '#888',
        borderRadius : '50%',
        display : 'inline-block',
        width : '20px',
        height : '20px',
        cursor : 'pointer',
        marginLeft: '20px',
        marginRight: '20px'
    }

    var listyleActive = {
        background : 'rgb(255, 113, 70)',
        borderRadius : '50%',
        display : 'inline-block',
        width : '20px',
        height : '20px',
        cursor : 'pointer',
        marginLeft: '20px',
        marginRight: '20px',
    }


    return (
        <li style={this.props.active ? listyleActive : listyle} onClick={this.handleClick} ></li>
    );
  }
}

// only for validation purpose!
// if the component is created without the prop "onSelect" and if this prop is not a function then there will be a warning
SliderItem.propTypes = {
  onSelect: React.PropTypes.func.isRequired 
}

export default SliderItem;
