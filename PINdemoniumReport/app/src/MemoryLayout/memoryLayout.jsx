import React from 'react';

import Slider from './slider.jsx'


class MemoryLayout extends React.Component {

  constructor(){
    super()
    this._setHeight = this._setHeight.bind(this)
    this._drawMemory = this._drawMemory.bind(this)
    this._drawDump = this._drawDump.bind(this)
    this._drawArrow = this._drawArrow.bind(this)
  }

  //set the proper dimensions for the canvas object based on the viewport dimension
  _setHeight(){
    var navbarHeight = document.getElementById('navbar').offsetHeight;
    var informationHeight = document.getElementById('information').offsetHeight;
    var sliderHeight = document.getElementById('slider').offsetHeight;

    this.canvas.width = window.innerWidth - 30;
    this.canvas.height = window.innerHeight - (navbarHeight + informationHeight + sliderHeight + 50);
  }

  _drawMemory(){
    // draw the rectangle representing the memory of the process
    var memorySpace = new createjs.Shape();
    memorySpace.width = this.canvas.width / 3
    memorySpace.height = this.canvas.height - 50 
    memorySpace.x = memorySpace.width
    memorySpace.y = 50
    memorySpace.graphics.beginFill("DeepSkyBlue").drawRect(0, 0, memorySpace.width, memorySpace.height);

    // draw the label above the rectangle representing the process
    var labelMemorySpace = new createjs.Text("Memory Layout", "30px Arial", "black");
    // center the label on the rectangle
    var labelMemorySpaceBounds = labelMemorySpace.getBounds()
    labelMemorySpace.x = memorySpace.width + ( (memorySpace.width - labelMemorySpaceBounds.width) / 2)

    // draw the addresses label on the right of the memory layout
    var labelMemoryFirstAddress = new createjs.Text("0x00", "20px Arial", "red");
    var labelMemoryLastAddress = new createjs.Text("0xff", "20px Arial", "red");
    var labelmemoryAddressX = memorySpace.width * 2 + 10
    labelMemoryFirstAddress.x = labelmemoryAddressX
    labelMemoryFirstAddress.y = 50
    labelMemoryLastAddress.x = labelmemoryAddressX
    labelMemoryLastAddress.y = memorySpace.height - (labelMemoryLastAddress.getBounds().height) + 50

    this.stage.addChild(memorySpace, labelMemorySpace, labelMemoryFirstAddress, labelMemoryLastAddress);
    // update the canvas
    this.stage.update();
  }


  _drawDump(y, name){
    // draw the rectangle representing the memory of the process
    var dumpShape = new createjs.Shape()
    dumpShape.name = name
    dumpShape.width = this.canvas.width / 2.5
    dumpShape.height = 100
    dumpShape.x = (this.canvas.width - dumpShape.width)/2
    dumpShape.y = y
    dumpShape.graphics.beginFill("red").drawRect(0, 0, dumpShape.width, dumpShape.height);
    
    // draw the label above the rectangle representing the process
    var labelDumpShape = new createjs.Text(name, "30px Arial", "white");
    // center the label on the rectangle
    var labelDumpShapeBounds = labelDumpShape.getBounds()
    labelDumpShape.x = dumpShape.x + ( (dumpShape.width - labelDumpShapeBounds.width) / 2)
    labelDumpShape.y = dumpShape.y + ( ( dumpShape.height - labelDumpShapeBounds.height) / 2)
    
    // draw the addresses label on the right of the memory layout
    var labelDumpShapeFirstAddress = new createjs.Text("0x00400040", "20px Arial", "blue");
    var labelDumpShapeLastAddress = new createjs.Text("0x00411040", "20px Arial", "blue");
    labelDumpShapeFirstAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeFirstAddress.y = dumpShape.y
    labelDumpShapeLastAddress.x = dumpShape.width + dumpShape.x + 10
    labelDumpShapeLastAddress.y = dumpShape.y +   dumpShape.height - (labelDumpShapeLastAddress.getBounds().height)

    this.stage.addChild(dumpShape, labelDumpShape, labelDumpShapeFirstAddress, labelDumpShapeLastAddress);
    // update the canvas
    this.stage.update();
  }

  _drawArrow(){

    var dump_1 = this.stage.getChildByName("DUMP_1")
    var dump_2 = this.stage.getChildByName("DUMP_2")

    var beginArrowX = dump_1.x
    var beginArrowY = dump_1.y + (dump_1.height / 2)
    var leftOffsetArrow = 60
    var middleArriveDumpY = dump_2.y + (dump_2.height / 2)
    var arrow = new createjs.Shape();
    arrow.name = "arrow"
    arrow.graphics.setStrokeStyle(4)
                  .beginStroke(createjs.Graphics.getRGB(0, 0, 0))

                  .moveTo(beginArrowX, beginArrowY)                             // move the corsor on the left border of the start dump
                                                                                // and in the middle of its height
                  
                  .lineTo(beginArrowX - leftOffsetArrow, beginArrowY)           // draw a straight horizontal segment 60px on the left

                  .lineTo(beginArrowX - leftOffsetArrow, middleArriveDumpY)     // draw a straight vertical line until the middle of the arrive dump

                  .lineTo(beginArrowX, middleArriveDumpY)                       // draw a straight horizontal line until the left border of the final dump

                  .moveTo(beginArrowX - 25,  middleArriveDumpY - 13)            // draw the arrowhead

                  .lineTo(beginArrowX, middleArriveDumpY)                       // draw the arrowhead

                  .lineTo(beginArrowX - 25,  middleArriveDumpY + 13)            // draw the arrowhead
    

    this.stage.addChild(arrow);
    this.stage.update();

  }

  //callback of reactjs called when th component mounting is finished
  componentDidMount() {
    this.canvas = document.getElementById('memoryLayoutCanvas'); 
    this._setHeight() 
    this.stage = new createjs.Stage("memoryLayoutCanvas");
    this._drawMemory()
    this._drawDump(400, "DUMP_1")
    this._drawDump(100, "DUMP_2")
    this._drawArrow()

    //this.stage.removeChild(this.stage.getChildByName("arrow"))
    //this.stage.update()
  }

  render () {

    var highlightBorder = {
      marginTop: '15px',
      borderTop : '#f33901 1px solid'
    }

    return (
      <div>
        <canvas id="memoryLayoutCanvas"></canvas>

        <div className="row" id="slider" style={highlightBorder}>
            <div className="col-sm-12" >
                <Slider />
            </div>
        </div>
      </div>
    );

  }

}

export default MemoryLayout;






